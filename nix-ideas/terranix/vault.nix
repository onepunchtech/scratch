{ lib, ir, irLib }:
let
  inherit (lib)
    mkOption mkEnableOption types
    mapAttrsToList flatten foldl'
    recursiveUpdate optionalAttrs;

  mergeAll = foldl' recursiveUpdate {};

  # ---------------------------------------------------------------------------
  # Options submodules — 1:1 with Vault terraform resource types
  # ---------------------------------------------------------------------------

  # vault_kv_secret_v2
  kvSecretOptions = { name, ... }: {
    options = {
      mount             = mkOption { type = types.str; default = "secret"; };
      path              = mkOption {
        type        = types.str;
        default     = name;
        description = "Secret path within the mount. Defaults to the attribute name.";
      };
      data              = mkOption {
        type        = types.attrsOf types.anything;
        default     = {};
        description = "Key-value pairs. Values may be IR expressions or plain strings.";
      };
      deleteAllVersions = mkOption { type = types.bool; default = false; };
      out = {
        pathRef = mkOption {
          type        = types.str;
          readOnly    = true;
          default     = name;
          description = "The secret path. Category 1 — use directly in ESO manifests.";
        };
      };
    };
  };

  # vault_policy
  policyOptions = { name, ... }: {
    options = {
      policy = mkOption {
        type        = types.str;
        description = "HCL policy document string.";
      };
      out.nameRef = mkOption {
        type        = types.str;
        readOnly    = true;
        default     = name;
        description = "Policy name. Category 1 — use in token_policies lists.";
      };
    };
  };

  # vault_auth_backend + vault_kubernetes_auth_backend_config
  k8sAuthOptions = { ... }: {
    options = {
      enable = mkEnableOption "Vault Kubernetes auth backend";
      mount  = mkOption { type = types.str; default = "kubernetes"; };
      out = {
        mountRef = mkOption {
          type        = types.str;
          readOnly    = true;
          default     = "kubernetes";
          description = "Auth backend mount path. Category 1.";
        };
      };
    };
  };

  # vault_kubernetes_auth_backend_role
  k8sAuthRoleOptions = { name, ... }: {
    options = {
      backend = mkOption {
        type        = types.str;
        default     = "kubernetes";
        description = "k8s auth backend mount path. Use k8sAuth.out.mountRef.";
      };
      serviceAccountNames      = mkOption { type = types.listOf types.str; };
      serviceAccountNamespaces = mkOption { type = types.listOf types.str; };
      tokenPolicies            = mkOption { type = types.listOf types.str; default = []; };
      tokenTtl                 = mkOption { type = types.int; default = 3600; };
      out.roleNameRef = mkOption {
        type        = types.str;
        readOnly    = true;
        default     = name;
        description = "Role name. Category 1.";
      };
    };
  };

  # vault_aws_secret_backend_role
  awsBackendRoleOptions = { name, ... }: {
    options = {
      backend        = mkOption { type = types.str; description = "Vault AWS secrets engine mount path."; };
      credentialType = mkOption { type = types.enum [ "iam_user" "assumed_role" ]; default = "iam_user"; };
      # IR expression — use iamUsers.<n>.out.arnRef or iamRoles.<n>.out.arnRef from aws.nix
      iamArn         = mkOption {
        type        = types.anything;
        description = "IR ref to the IAM user or role ARN. Use aws.providers.<n>.iamUsers.<n>.out.arnRef.";
      };
      out.credPath = mkOption {
        type        = types.str;
        readOnly    = true;
        default     = name;
        description = ''
          Vault credential path for this role: <backend>/creds/<name>.
          Category 1 — use in Vault Agent annotations on pods.
        '';
      };
    };
  };

  # vault_mount (PKI)
  pkiMountOptions = { name, ... }: {
    options = {
      defaultLeaseTtlSeconds = mkOption { type = types.int; default = 3600; };
      maxLeaseTtlSeconds     = mkOption { type = types.int; default = 315360000; };
      out = {
        # Category 1 — path is an input you defined
        mountPath = mkOption {
          type        = types.str;
          readOnly    = true;
          default     = "pki/${name}";
          description = "PKI mount path. Category 1 — use in cert-manager ClusterIssuer manifests.";
        };
        pathRef = mkOption {
          type        = types.anything;
          readOnly    = true;
          default     = ir.mkRef "vault_mount" "vault_pki_${name}" "path";
          description = "IR ref to mount path. Use within same terraform root.";
        };
      };
    };
  };

  # vault_pki_secret_backend_root_cert
  pkiRootCertOptions = { name, ... }: {
    options = {
      mountRef     = mkOption { type = types.anything; description = "IR ref to PKI mount path. Use pkiMounts.<n>.out.pathRef."; };
      commonName   = mkOption { type = types.str; };
      organization = mkOption { type = types.str; default = ""; };
      country      = mkOption { type = types.str; default = ""; };
      ttl          = mkOption { type = types.str; default = "87600h"; };
    };
  };

  # vault_pki_secret_backend_role
  pkiRoleOptions = { name, ... }: {
    options = {
      mountRef        = mkOption { type = types.anything; description = "IR ref to PKI mount path."; };
      allowedDomains  = mkOption { type = types.listOf types.str; default = []; };
      allowSubdomains = mkOption { type = types.bool; default = true; };
      maxTtl          = mkOption { type = types.str; default = "72h"; };
      keyUsage        = mkOption {
        type    = types.listOf types.str;
        default = [ "DigitalSignature" "KeyAgreement" "KeyEncipherment" ];
      };
    };
  };

  # vault_pki_secret_backend_config_urls
  pkiConfigUrlsOptions = { ... }: {
    options = {
      mountRef = mkOption { type = types.anything; description = "IR ref to PKI mount path."; };
      # vault_address is injected via ir.mkVar at toIR time
      # paths are computed from the mount name
    };
  };

  # ---------------------------------------------------------------------------
  # toIR helpers
  # ---------------------------------------------------------------------------

  kvSecretToIR = name: cfg:
    ir.mkResource {
      type   = "vault_kv_secret_v2";
      name   = "vault_kv_${lib.strings.replaceStrings ["-" "/"] ["_" "_"] name}";
      config = {
        mount               = cfg.mount;
        name                = cfg.path;
        delete_all_versions = cfg.deleteAllVersions;
        data_json           = cfg.data;
      };
    };

  policyToIR = name: cfg:
    ir.mkResource {
      type   = "vault_policy";
      name   = "vault_policy_${lib.strings.replaceStrings ["-"] ["_"] name}";
      config = { name = name; policy = cfg.policy; };
      outputs."vault_policy_${lib.strings.replaceStrings ["-"] ["_"] name}_name" = name;
    };

  k8sAuthToIR = cfg:
    if !cfg.enable then []
    else [
      (ir.mkResource {
        type    = "vault_auth_backend";
        name    = "kubernetes";
        config  = { type = "kubernetes"; path = cfg.mount; };
        outputs."vault_k8s_auth_path" = ir.mkRef "vault_auth_backend" "kubernetes" "path";
      })
      (ir.mkResource {
        type   = "vault_kubernetes_auth_backend_config";
        name   = "kubernetes";
        config = {
          backend            = ir.mkRef "vault_auth_backend" "kubernetes" "path";
          kubernetes_host    = ir.mkVar "vault_k8s_host";
          kubernetes_ca_cert = ir.mkVar "vault_k8s_ca_cert";
          token_reviewer_jwt = ir.mkVar "vault_k8s_token_reviewer_jwt";
        };
      })
    ];

  k8sAuthRoleToIR = name: cfg:
    ir.mkResource {
      type   = "vault_kubernetes_auth_backend_role";
      name   = "vault_k8s_role_${lib.strings.replaceStrings ["-"] ["_"] name}";
      config = {
        backend                          = cfg.backend;
        role_name                        = name;
        bound_service_account_names      = cfg.serviceAccountNames;
        bound_service_account_namespaces = cfg.serviceAccountNamespaces;
        token_policies                   = cfg.tokenPolicies;
        token_ttl                        = cfg.tokenTtl;
      };
    };

  awsBackendRoleToIR = name: cfg:
    ir.mkResource {
      type   = "vault_aws_secret_backend_role";
      name   = "vault_aws_role_${lib.strings.replaceStrings ["-"] ["_"] name}";
      config = {
        backend         = cfg.backend;
        name            = name;
        credential_type = cfg.credentialType;
      } // (
        if cfg.credentialType == "iam_user"
        then { iam_users = [ cfg.iamArn ]; }
        else { role_arns = [ cfg.iamArn ]; }
      );
    };

  pkiMountToIR = name: cfg:
    ir.mkResource {
      type    = "vault_mount";
      name    = "vault_pki_${lib.strings.replaceStrings ["-"] ["_"] name}";
      config  = {
        path                      = "pki/${name}";
        type                      = "pki";
        default_lease_ttl_seconds = cfg.defaultLeaseTtlSeconds;
        max_lease_ttl_seconds     = cfg.maxLeaseTtlSeconds;
      };
      outputs."vault_pki_${lib.strings.replaceStrings ["-"] ["_"] name}_path" =
        ir.mkRef "vault_mount" "vault_pki_${lib.strings.replaceStrings ["-"] ["_"] name}" "path";
    };

  pkiRootCertToIR = name: cfg:
    ir.mkResource {
      type   = "vault_pki_secret_backend_root_cert";
      name   = "vault_pki_cert_${lib.strings.replaceStrings ["-"] ["_"] name}";
      config = {
        backend     = cfg.mountRef;
        type        = "internal";
        common_name = cfg.commonName;
        ttl         = cfg.ttl;
      }
      // optionalAttrs (cfg.organization != "") { organization = cfg.organization; }
      // optionalAttrs (cfg.country      != "") { country      = cfg.country; };
    };

  pkiRoleToIR = name: cfg:
    ir.mkResource {
      type   = "vault_pki_secret_backend_role";
      name   = "vault_pki_role_${lib.strings.replaceStrings ["-"] ["_"] name}";
      config = {
        backend          = cfg.mountRef;
        name             = name;
        allowed_domains  = cfg.allowedDomains;
        allow_subdomains = cfg.allowSubdomains;
        max_ttl          = cfg.maxTtl;
        key_usage        = cfg.keyUsage;
      };
    };

  pkiConfigUrlsToIR = name: cfg:
    ir.mkResource {
      type   = "vault_pki_secret_backend_config_urls";
      name   = "vault_pki_urls_${lib.strings.replaceStrings ["-"] ["_"] name}";
      config = {
        backend                 = cfg.mountRef;
        issuing_certificates    = [ (ir.mkConcat [ (ir.mkVar "vault_address") "/v1/pki/${name}/ca" ]) ];
        crl_distribution_points = [ (ir.mkConcat [ (ir.mkVar "vault_address") "/v1/pki/${name}/crl" ]) ];
      };
    };

in
{
  options = { ... }: {
    options = {
      # vault_auth_backend + vault_kubernetes_auth_backend_config
      k8sAuth = mkOption {
        type    = types.submodule k8sAuthOptions;
        default = {};
      };

      # vault_kubernetes_auth_backend_role
      k8sAuthRoles = mkOption {
        type    = types.attrsOf (types.submodule k8sAuthRoleOptions);
        default = {};
      };

      # vault_aws_secret_backend_role
      awsBackendRoles = mkOption {
        type        = types.attrsOf (types.submodule awsBackendRoleOptions);
        default     = {};
        description = ''
          Vault AWS secret backend roles. Each connects an IAM user or role
          to a Vault credential path. Reference iamArn from aws.nix out.arnRef.
        '';
      };

      # vault_kv_secret_v2
      kvSecrets = mkOption {
        type    = types.attrsOf (types.submodule kvSecretOptions);
        default = {};
      };

      # vault_policy
      policies = mkOption {
        type    = types.attrsOf (types.submodule policyOptions);
        default = {};
      };

      # PKI resources — separate resource types as flat siblings
      pkiMounts     = mkOption { type = types.attrsOf (types.submodule pkiMountOptions);      default = {}; };
      pkiRootCerts  = mkOption { type = types.attrsOf (types.submodule pkiRootCertOptions);   default = {}; };
      pkiRoles      = mkOption { type = types.attrsOf (types.submodule pkiRoleOptions);       default = {}; };
      pkiConfigUrls = mkOption { type = types.attrsOf (types.submodule pkiConfigUrlsOptions); default = {}; };
    };
  };

  # Single toIR — returns complete IR attrset
  toIR = vaultCfg:
    let
      resources = flatten [
        (k8sAuthToIR vaultCfg.k8sAuth)
        (mapAttrsToList k8sAuthRoleToIR   vaultCfg.k8sAuthRoles)
        (mapAttrsToList awsBackendRoleToIR vaultCfg.awsBackendRoles)
        (mapAttrsToList kvSecretToIR      vaultCfg.kvSecrets)
        (mapAttrsToList policyToIR        vaultCfg.policies)
        (mapAttrsToList pkiMountToIR      vaultCfg.pkiMounts)
        (mapAttrsToList pkiRootCertToIR   vaultCfg.pkiRootCerts)
        (mapAttrsToList pkiRoleToIR       vaultCfg.pkiRoles)
        (mapAttrsToList pkiConfigUrlsToIR vaultCfg.pkiConfigUrls)
      ];
    in {
      resources   = resources;
      outputs     = irLib.liftOutputs resources;
      providers   = { vault = { providerType = "vault"; address = ir.mkVar "vault_address"; }; };
      variables   = mergeAll [
        (optionalAttrs vaultCfg.k8sAuth.enable {
          vault_k8s_host = {
            type        = "string";
            description = "Kubernetes API server URL.";
          };
          vault_k8s_ca_cert = {
            type = "string"; sensitive = true;
            description = "PEM-encoded CA cert for the Kubernetes API server.";
          };
          vault_k8s_token_reviewer_jwt = {
            type = "string"; sensitive = true;
            description = "ServiceAccount JWT for Vault token review.";
          };
        })
      ];
      remoteState = [];
    };
}
