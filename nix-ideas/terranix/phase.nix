{ lib, pkgs, terranix, irLib, awsLib, vaultLib, auth0Lib
, phaseName
, stateKeyPrefix
, precedingPhases
}:

let
  inherit (lib)
    mkOption mkEnableOption types
    foldl' recursiveUpdate optionalAttrs;

  mergeAll = foldl' recursiveUpdate {};

in

{ name, config, ... }: {

  options = {

    enable = mkEnableOption "terraform ${phaseName} phase";

    aws   = mkOption { type = types.submodule awsLib.options;   default = {}; };
    vault = mkOption { type = types.submodule vaultLib.options; default = {}; };
    auth0 = mkOption { type = types.submodule auth0Lib.options; default = {}; };

    variables = mkOption {
      type = types.attrsOf (types.submodule {
        options = {
          type        = mkOption { type = types.str;      default = "string"; };
          description = mkOption { type = types.str;      default = ""; };
          default     = mkOption { type = types.anything; default = null; };
          sensitive   = mkOption { type = types.bool;     default = false; };
        };
      });
      default     = {};
      description = "Additional terraform variable declarations. User-declared, merged last.";
    };

    extraConfig = mkOption {
      type        = types.attrsOf types.anything;
      default     = {};
      description = "Raw terranix config. Merged last, wins on conflict.";
    };

    out = {
      ir = mkOption {
        type        = irLib.IR;
        readOnly    = true;
        description = "Assembled IR for this phase.";
      };
      configJson = mkOption {
        type        = types.package;
        readOnly    = true;
        description = "Derivation producing main.tf.json for this phase.";
      };
    };
  };

  config =
    let
      # Merge all provider IRs into one — each provider owns its resources,
      # outputs, providers, and variables
      mergedIR = irLib.mergeIRs [
        (awsLib.toIR   config.aws)
        (vaultLib.toIR config.vault)
        (auth0Lib.toIR config.auth0)
      ];

      # Standard variables always present — gitlab token for state backend
      # vault_address and auth0_domain derived from provider presence
      standardVariables = {
        gitlab_token = {
          type      = "string";
          sensitive = true;
          description = "GitLab CI job token for state backend auth (CI_JOB_TOKEN).";
        };
      };

      # Provider credential variables derived from which providers are present
      providerCredentialVariables =
        mergeAll [
          (optionalAttrs (mergedIR.providers ? vault) {
            vault_address = {
              type        = "string";
              description = "Vault server address e.g. https://vault.myplatform.io";
            };
          })
          (optionalAttrs (mergedIR.providers ? auth0) {
            auth0_domain = {
              type        = "string";
              description = "Auth0 tenant domain e.g. myplatform.eu.auth0.com";
            };
            auth0_client_id = {
              type = "string"; sensitive = true;
              description = "Auth0 management API client ID.";
            };
            auth0_client_secret = {
              type = "string"; sensitive = true;
              description = "Auth0 management API client secret.";
            };
          })
        ];

      resolvedVariables = mergeAll [
        standardVariables
        providerCredentialVariables
        mergedIR.variables        # provider-derived variables
        config.variables          # user-declared last — wins on conflict
      ];

    in {
      out.ir = mergedIR // {
        remoteState = [];   # populated by cluster module
        outputs     = {};   # populated by cluster module
        variables   = resolvedVariables;
      };

      out.configJson =
        let
          toTerranix = import ./toTerranix.nix { inherit lib; };
          tfAttrset  = mergeAll [
            (toTerranix config.out.ir)
            config.extraConfig
          ];
        in
          terranix.lib.terranixConfiguration {
            inherit pkgs;
            modules = [ tfAttrset ];
          };
    };
}
