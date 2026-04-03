{ lib, pkgs, terranix, config, ... }:

let
  inherit (lib)
    mkOption types mapAttrs mapAttrsToList
    foldl' recursiveUpdate flatten filter
    nameValuePair listToAttrs unique
    concatStringsSep optionalAttrs;

  mergeAll = foldl' recursiveUpdate {};

  cfg = config.platform;

  irLib    = import ./ir.nix               { inherit lib; };
  awsLib   = import ./providers/aws.nix   { inherit lib; ir = irLib; inherit irLib; };
  vaultLib = import ./providers/vault.nix { inherit lib; ir = irLib; inherit irLib; };
  auth0Lib = import ./providers/auth0.nix { inherit lib; ir = irLib; inherit irLib; };

  phaseOrder = [ "infra" "bootstrap" "post-cluster" ];

  stateKey = clusterName: phase:
    concatStringsSep "--" [ cfg.project cfg.env cfg.slice clusterName phase ];

  stateKeyPrefix = clusterName:
    concatStringsSep "/" [ cfg.project cfg.env cfg.slice clusterName ];

  mkPhaseType = clusterName: phaseName:
    types.submodule (import ./phase.nix {
      inherit lib pkgs terranix irLib awsLib vaultLib auth0Lib phaseName;
      stateKeyPrefix  = stateKeyPrefix clusterName;
      precedingPhases = [];
    });

  # ---------------------------------------------------------------------------
  # Cross-phase output demand analysis
  # ---------------------------------------------------------------------------

  isRemoteRef = v: builtins.isAttrs v && v ? remoteRef;

  collectRemoteRefs = val:
    if      isRemoteRef       val then [ val.remoteRef ]
    else if builtins.isAttrs  val then flatten (map collectRemoteRefs (builtins.attrValues val))
    else if builtins.isList   val then flatten (map collectRemoteRefs val)
    else [];

  computeRequiredOutputs = clusterCfg: enabledPhases:
    let
      allRefs = flatten (map (phase:
        flatten (map (r: collectRemoteRefs r.config) clusterCfg.${phase}.out.ir.resources)
      ) enabledPhases);

      demandedByPhase = foldl' (acc: ref:
        acc // { ${ref.phase} = (acc.${ref.phase} or {}) // { ${ref.outputKey} = true; }; }
      ) {} allRefs;

    in
      mapAttrs (phaseName: demandedKeys:
        # Use liftOutputs to get the full output index including sensitive flags
        let allOutputs = irLib.liftOutputs clusterCfg.${phaseName}.out.ir.resources;
        in listToAttrs (mapAttrsToList (outputKey: _:
          nameValuePair outputKey (
            allOutputs.${outputKey} or
              (throw "Phase '${phaseName}' has no exportable output '${outputKey}'")
          )
        ) demandedKeys)
      ) demandedByPhase;

  # ---------------------------------------------------------------------------
  # Per-cluster package builder
  # ---------------------------------------------------------------------------

  buildClusterTerraform = clusterName: clusterCfg:
    let
      enabledPhases   = filter (p: clusterCfg.${p}.enable) phaseOrder;
      requiredOutputs = computeRequiredOutputs clusterCfg enabledPhases;

      phasesWithWiring = listToAttrs (map (phase:
        let
          referencedPhases = unique (map (ref: ref.phase) (
            flatten (map (r: collectRemoteRefs r.config) clusterCfg.${phase}.out.ir.resources)
          ));
          remoteStateEntries = map (p: {
            phase    = p;
            stateKey = stateKey clusterName p;
          }) referencedPhases;
        in nameValuePair phase (clusterCfg.${phase} // {
          out = clusterCfg.${phase}.out // {
            ir = clusterCfg.${phase}.out.ir // {
              outputs     = requiredOutputs.${phase} or {};
              remoteState = remoteStateEntries;
            };
          };
        })
      ) enabledPhases);

    in
      pkgs.runCommand "terraform-${clusterName}" {} ''
        ${concatStringsSep "\n" (mapAttrsToList (phase: phaseVal: ''
          mkdir -p $out/clusters/${clusterName}/terraform/${phase}
          cp ${phaseVal.out.configJson} \
             $out/clusters/${clusterName}/terraform/${phase}/main.tf.json
        '') phasesWithWiring)}
      '';

in
{
  options.platform = {

    project = mkOption { type = types.str; };
    env     = mkOption { type = types.str; };
    slice   = mkOption { type = types.str; };

    clusters = mkOption {
      type = types.attrsOf (types.submodule ({ name, config, ... }: {
        options = {
          infra        = mkOption { type = mkPhaseType name "infra";        default = {}; };
          bootstrap    = mkOption { type = mkPhaseType name "bootstrap";    default = {}; };
          post-cluster = mkOption { type = mkPhaseType name "post-cluster"; default = {}; };

          terraform.package = mkOption {
            type        = types.package;
            readOnly    = true;
            description = "Per-cluster derivation containing all enabled phase roots.";
          };
        };

        config.terraform.package = buildClusterTerraform name config;
      }));
    };
  };
}
