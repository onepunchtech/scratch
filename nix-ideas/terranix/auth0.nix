{ lib, ir, irLib }:
let
  inherit (lib)
    mkOption mkEnableOption types
    mapAttrsToList flatten foldl'
    recursiveUpdate optionalAttrs;

  mergeAll = foldl' recursiveUpdate {};

  tfName = name: lib.strings.replaceStrings [ "-" " " ] [ "_" "_" ] name;

  # ---------------------------------------------------------------------------
  # Options submodules — 1:1 with Auth0 terraform resource types
  # ---------------------------------------------------------------------------

  # auth0_client
  applicationOptions = { name, ... }: {
    options = {
      name              = mkOption { type = types.str; default = name; };
      appType           = mkOption { type = types.enum [ "spa" "regular_web" "native" "non_interactive" ]; };
      callbacks         = mkOption { type = types.listOf types.str; default = []; };
      allowedLogoutUrls = mkOption { type = types.listOf types.str; default = []; };
      allowedOrigins    = mkOption { type = types.listOf types.str; default = []; };
      webOrigins        = mkOption { type = types.listOf types.str; default = []; };
      grantTypes        = mkOption {
        type    = types.listOf (types.enum [
          "authorization_code" "implicit" "refresh_token" "client_credentials" "password"
        ]);
        default = [];
      };
      extraFields = mkOption { type = types.attrsOf types.anything; default = {}; };

      out = {
        clientIdRef = mkOption {
          type        = types.anything;
          readOnly    = true;
          default     = ir.mkRef "auth0_client" "auth0_${name}" "client_id";
          description = "IR ref to Auth0 client_id. Use within same terraform root.";
        };
        clientSecretRef = mkOption {
          type        = types.anything;
          readOnly    = true;
          default     = ir.mkRef "auth0_client" "auth0_${name}" "client_secret";
          description = "IR ref to Auth0 client_secret. Use within same terraform root.";
        };
      };
    };
  };

  # auth0_guardian — tenant-level MFA policy
  guardianOptions = { ... }: {
    options = {
      enable   = mkEnableOption "Auth0 Guardian MFA configuration";
      policy   = mkOption { type = types.enum [ "all-applications" "confidence-score" "never" ]; default = "all-applications"; };
      webauthnRoaming = {
        enable           = mkEnableOption "WebAuthn roaming authenticators (YubiKey etc.)";
        userVerification = mkOption {
          type    = types.enum [ "discouraged" "preferred" "required" ];
          default = "required";
        };
      };
      otp          = mkOption { type = types.bool; default = false; };
      email        = mkOption { type = types.bool; default = false; };
      recoveryCode = mkOption { type = types.bool; default = true; };
    };
  };

  # auth0_connection
  connectionOptions = { name, ... }: {
    options = {
      disableSignup          = mkOption { type = types.bool; default = true; };
      bruteForceProtection   = mkOption { type = types.bool; default = true; };
      passwordEnabled        = mkOption { type = types.bool; default = false; };
      passkeyEnabled         = mkOption { type = types.bool; default = true; };
      passkeyOptions = {
        challengeUi                  = mkOption { type = types.enum [ "both" "button" "autofill" ]; default = "both"; };
        localEnrollmentEnabled       = mkOption { type = types.bool; default = true; };
        progressiveEnrollmentEnabled = mkOption { type = types.bool; default = true; };
      };
      out = {
        idRef = mkOption {
          type        = types.anything;
          readOnly    = true;
          default     = ir.mkRef "auth0_connection" "auth0_conn_${name}" "id";
          description = "IR ref to this connection's id. Use in auth0_connection_clients.";
        };
        nameRef = mkOption {
          type        = types.str;
          readOnly    = true;
          default     = name;
          description = "Connection name. Category 1 — use in auth0_user connectionName.";
        };
      };
    };
  };

  # auth0_connection_clients
  connectionClientsOptions = { ... }: {
    options = {
      connectionIdRef = mkOption {
        type        = types.anything;
        description = "IR ref to connection id. Use connections.<n>.out.idRef.";
      };
      # IR refs to client ids — use applications.<n>.out.clientIdRef
      clientIds = mkOption {
        type        = types.listOf types.anything;
        description = "List of IR refs to client ids. Use applications.<n>.out.clientIdRef.";
      };
    };
  };

  # auth0_user
  userOptions = { ... }: {
    options = {
      email         = mkOption { type = types.str; };
      emailVerified = mkOption { type = types.bool; default = true; };
      connectionName = mkOption {
        type        = types.str;
        description = "Connection name. Use connections.<n>.out.nameRef.";
      };
      passwordVar = mkOption {
        type        = types.str;
        default     = "auth0_user_initial_password";
        description = "Terraform variable name for the throwaway initial password.";
      };
    };
  };

  # ---------------------------------------------------------------------------
  # toIR helpers
  # ---------------------------------------------------------------------------

  applicationToIR = name: cfg:
    ir.mkResource {
      type    = "auth0_client";
      name    = "auth0_${tfName name}";
      config  = { inherit (cfg) name; app_type = cfg.appType; }
        // optionalAttrs (cfg.callbacks         != []) { callbacks           = cfg.callbacks; }
        // optionalAttrs (cfg.allowedLogoutUrls  != []) { allowed_logout_urls = cfg.allowedLogoutUrls; }
        // optionalAttrs (cfg.allowedOrigins     != []) { allowed_origins     = cfg.allowedOrigins; }
        // optionalAttrs (cfg.webOrigins         != []) { web_origins         = cfg.webOrigins; }
        // optionalAttrs (cfg.grantTypes         != []) { grant_types         = cfg.grantTypes; }
        // cfg.extraFields;
      outputs = {
        "auth0_${tfName name}_client_id" = ir.mkRef "auth0_client" "auth0_${tfName name}" "client_id";
      };
      sensitiveOutputs = {
        "auth0_${tfName name}_client_secret" = ir.mkRef "auth0_client" "auth0_${tfName name}" "client_secret";
      };
    };

  guardianToIR = cfg:
    if !cfg.enable then []
    else [(ir.mkResource {
      type   = "auth0_guardian";
      name   = "mfa";
      config = {
        policy        = cfg.policy;
        otp           = cfg.otp;
        email         = cfg.email;
        recovery_code = cfg.recoveryCode;
      }
      // optionalAttrs cfg.webauthnRoaming.enable {
        webauthn_roaming = {
          enabled           = true;
          user_verification = cfg.webauthnRoaming.userVerification;
        };
      };
    })];

  connectionToIR = name: cfg:
    ir.mkResource {
      type   = "auth0_connection";
      name   = "auth0_conn_${tfName name}";
      config = {
        name     = name;
        strategy = "auth0";
        options  = {
          disable_signup         = cfg.disableSignup;
          brute_force_protection = cfg.bruteForceProtection;
          mfa = [{ active = true; return_enroll_settings = true; }];
          authentication_methods = [{
            passkey  = [{ enabled = cfg.passkeyEnabled; }];
            password = [{ enabled = cfg.passwordEnabled; }];
          }];
        }
        // optionalAttrs cfg.passkeyEnabled {
          passkey_options = [{
            challenge_ui                   = cfg.passkeyOptions.challengeUi;
            local_enrollment_enabled       = cfg.passkeyOptions.localEnrollmentEnabled;
            progressive_enrollment_enabled = cfg.passkeyOptions.progressiveEnrollmentEnabled;
          }];
        };
      };
    };

  connectionClientsToIR = name: cfg:
    ir.mkResource {
      type   = "auth0_connection_clients";
      name   = "auth0_conn_clients_${tfName name}";
      config = {
        connection_id   = cfg.connectionIdRef;
        enabled_clients = cfg.clientIds;
      };
    };

  userToIR = name: cfg:
    ir.mkResource {
      type   = "auth0_user";
      name   = "auth0_user_${tfName name}";
      config = {
        connection_name = cfg.connectionName;
        email           = cfg.email;
        email_verified  = cfg.emailVerified;
        password        = ir.mkVar cfg.passwordVar;
      };
    };

in
{
  options = { ... }: {
    options = {
      guardian          = mkOption { type = types.submodule guardianOptions;                             default = {}; };
      connections       = mkOption { type = types.attrsOf (types.submodule connectionOptions);           default = {}; };
      connectionClients = mkOption { type = types.attrsOf (types.submodule connectionClientsOptions);    default = {}; };
      applications      = mkOption { type = types.attrsOf (types.submodule applicationOptions);         default = {}; };
      users             = mkOption { type = types.attrsOf (types.submodule userOptions);                default = {}; };
    };
  };

  # Single toIR — returns complete IR attrset
  toIR = auth0Cfg:
    let
      resources = flatten [
        (guardianToIR auth0Cfg.guardian)
        (mapAttrsToList connectionToIR        auth0Cfg.connections)
        (mapAttrsToList connectionClientsToIR auth0Cfg.connectionClients)
        (mapAttrsToList applicationToIR       auth0Cfg.applications)
        (mapAttrsToList userToIR              auth0Cfg.users)
      ];
    in {
      resources   = resources;
      outputs     = irLib.liftOutputs resources;
      providers   = { auth0 = { providerType = "auth0"; domain = ir.mkVar "auth0_domain"; }; };
      variables   = {
        auth0_user_initial_password = {
          type      = "string";
          sensitive = true;
          description = "Throwaway password required by Auth0 API on user creation. Never usable for login.";
        };
      };
      remoteState = [];
    };
}
