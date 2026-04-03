{ lib }:
let
  inherit (lib) mkOption types;

in
rec {

  # ---------------------------------------------------------------------------
  # Expression constructors
  #
  # Plain nix values tagged with __type. The module system never needs to
  # discriminate between them — renderExpr in each backend handles that.
  # ---------------------------------------------------------------------------

  mkVar         = name:               { __type = "var";         var          = name; };
  mkRef         = type: name: attr:   { __type = "ref";         ref          = { inherit type name attr; }; };
  mkData        = type: name: attr:   { __type = "data";        data         = { inherit type name attr; }; };
  mkRemoteRef   = phase: outputKey:   { __type = "remoteRef";   remoteRef    = { inherit phase outputKey; }; };
  mkProviderRef = providerType: alias: { __type = "providerRef"; providerRef  = { inherit providerType alias; }; };
  mkConcat      = parts:              { __type = "concat";      parts        = parts; };

  isExpr = v: builtins.isAttrs v && v ? __type;

  # ---------------------------------------------------------------------------
  # IR combinators
  # ---------------------------------------------------------------------------

  emptyIR = {
    resources   = [];
    outputs     = {};
    providers   = {};
    variables   = {};
    remoteState = [];
  };

  # Merge a list of complete IR attrsets into one.
  # resources and remoteState are concatenated (ordered).
  # outputs, providers, variables are merged (last wins on conflict).
  mergeIRs = irs:
    lib.foldl' (acc: ir: {
      resources   = acc.resources   ++ ir.resources;
      outputs     = acc.outputs     // ir.outputs;
      providers   = lib.recursiveUpdate acc.providers   ir.providers;
      variables   = lib.recursiveUpdate acc.variables   ir.variables;
      remoteState = acc.remoteState ++ ir.remoteState;
    }) emptyIR irs;

  # Lift all resource outputs into a flat ir.outputs-shaped attrset.
  # Carries sensitive flag through from sensitiveOutputs.
  liftOutputs = resources:
    lib.foldl' (acc: resource:
      acc
      // lib.mapAttrs (_: expr: {
           value       = expr;
           sensitive   = false;
           description = "Exported from ${resource.type}.${resource.name}";
         }) resource.outputs
      // lib.mapAttrs (_: expr: {
           value       = expr;
           sensitive   = true;
           description = "Exported from ${resource.type}.${resource.name} (sensitive)";
         }) (resource.sensitiveOutputs or {})
    ) {} resources;

  # ---------------------------------------------------------------------------
  # mkResource / mkDataSource
  # ---------------------------------------------------------------------------

  mkResource =
    { type
    , name
    , config
    , outputs ? {}
    , sensitiveOutputs ? {}
    }:
    { inherit type name config outputs sensitiveOutputs; isDataSource = false; };

  # liftOutputs :: [resource] → { outputKey → { value, description, sensitive } }
  #
  # Collects all outputs and sensitiveOutputs from a resource list into a flat
  # attrset suitable for ir.outputs. Used by provider toIR functions and by
  # the cluster module when generating Vault KV secrets and terraform output{} blocks.
  liftOutputs = resources:
    lib.foldl' (acc: resource:
      acc
      // lib.mapAttrs (_: expr: {
           value       = expr;
           sensitive   = false;
           description = "Exported from ${resource.type}.${resource.name}";
         }) resource.outputs
      // lib.mapAttrs (_: expr: {
           value       = expr;
           sensitive   = true;
           description = "Exported from ${resource.type}.${resource.name} (sensitive)";
         }) (resource.sensitiveOutputs or {})
    ) {} resources;

  mkDataSource =
    { type
    , name
    , config
    }:
    { inherit type name config; outputs = {}; isDataSource = true; };

  # ---------------------------------------------------------------------------
  # IR type
  # ---------------------------------------------------------------------------

  IR = types.submodule {
    options = {

      resources = mkOption {
        description = "All resources and data sources declared in this phase.";
        default     = [];
        type        = types.listOf (types.submodule {
          options = {
            type             = mkOption { type = types.str; };
            name             = mkOption { type = types.str; };
            config           = mkOption { type = types.attrsOf types.anything; };
            outputs          = mkOption { type = types.attrsOf types.anything; default = {}; };
            sensitiveOutputs = mkOption { type = types.attrsOf types.anything; default = {}; };
            isDataSource     = mkOption { type = types.bool; default = false; };
          };
        });
      };

      remoteState = mkOption {
        internal    = true;
        readOnly    = true;
        description = "Remote state sources this phase reads. Populated by the cluster module.";
        default     = [];
        type        = types.listOf (types.submodule {
          options = {
            phase    = mkOption { type = types.str; };
            stateKey = mkOption { type = types.str; };
          };
        });
      };

      outputs = mkOption {
        internal    = true;
        readOnly    = true;
        description = "Output values this phase must emit. Populated by the cluster module.";
        default     = {};
        type        = types.attrsOf (types.submodule {
          options = {
            value       = mkOption { type = types.anything; };
            description = mkOption { type = types.str; default = ""; };
            sensitive   = mkOption { type = types.bool; default = false; };
          };
        });
      };

      providers = mkOption {
        description = ''
          Provider configuration for this phase.
          Values may use IR expression constructors.
          Backends render expressions into their own syntax.
        '';
        default = {};
        type    = types.attrsOf types.anything;
      };

      variables = mkOption {
        internal    = true;
        readOnly    = true;
        description = "Input variable declarations. Populated by phase.nix.";
        default     = {};
        type        = types.attrsOf (types.submodule {
          options = {
            type        = mkOption { type = types.str;     default = "string"; };
            description = mkOption { type = types.str;     default = ""; };
            default     = mkOption { type = types.anything; default = null; };
            sensitive   = mkOption { type = types.bool;    default = false; };
          };
        });
      };

    };
  };
}
