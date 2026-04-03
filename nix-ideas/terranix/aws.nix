{ lib, ir, irLib }:
let
  inherit (lib)
    mkOption mkEnableOption types
    mapAttrsToList flatten foldl'
    recursiveUpdate optionalAttrs
    nameValuePair listToAttrs strings;

  mergeAll = foldl' recursiveUpdate {};

  tfName = name: strings.replaceStrings [ "-" "/" " " ] [ "_" "_" "_" ] name;

  # ---------------------------------------------------------------------------
  # Action sets — exported for user convenience
  # ---------------------------------------------------------------------------

  s3Actions = {
    read-only  = [ "s3:GetObject" "s3:ListBucket" ];
    write-only = [ "s3:PutObject" "s3:DeleteObject" ];
    read-write = [ "s3:GetObject" "s3:ListBucket" "s3:PutObject" "s3:DeleteObject" ];
  };

  dynamoActions = {
    read-only  = [
      "dynamodb:GetItem"    "dynamodb:Query"
      "dynamodb:Scan"       "dynamodb:BatchGetItem"
    ];
    write-only = [
      "dynamodb:PutItem"    "dynamodb:UpdateItem"
      "dynamodb:DeleteItem" "dynamodb:BatchWriteItem"
    ];
    read-write = [
      "dynamodb:GetItem"    "dynamodb:Query"
      "dynamodb:Scan"       "dynamodb:BatchGetItem"
      "dynamodb:PutItem"    "dynamodb:UpdateItem"
      "dynamodb:DeleteItem" "dynamodb:BatchWriteItem"
    ];
  };

  # ---------------------------------------------------------------------------
  # Statement helpers — exported so users don't memorise action lists
  # Takes resource out.* attrset, returns plain statement attrset
  # ---------------------------------------------------------------------------

  s3Statement = bucketOut: access: {
    effect    = "Allow";
    actions   = s3Actions.${access};
    resources = [
      bucketOut.arnRef
      (ir.mkConcat [ bucketOut.arnRef "/*" ])
    ];
  };

  dynamoStatement = tableOut: access: {
    effect    = "Allow";
    actions   = dynamoActions.${access};
    resources = [
      tableOut.arnRef
      (ir.mkConcat [ tableOut.arnRef "/index/*" ])
    ];
  };

  stsTrustStatement = principalArnExpr: {
    effect     = "Allow";
    actions    = [ "sts:AssumeRole" ];
    principals = [{
      type        = "AWS";
      identifiers = [ principalArnExpr ];
    }];
  };

  # ---------------------------------------------------------------------------
  # Policy document reference resolution
  #
  # policyDocumentRef accepts either:
  #   - a string name — resolved to ir.mkData against policyDocuments in this provider
  #   - an IR expression — passed through verbatim (e.g. out.jsonRef from another provider)
  #
  # Validation: string names are checked against providerCfg.policyDocuments at toIR time.
  # ---------------------------------------------------------------------------

  resolvePolicy = providerCfg: ref:
    if builtins.isString ref
    then
      if providerCfg.policyDocuments ? ${ref}
      then ir.mkData "aws_iam_policy_document" (tfName ref) "json"
      else throw ''
        aws.nix: policyDocumentRef "${ref}" not found in policyDocuments.
        Available: ${toString (lib.attrNames providerCfg.policyDocuments)}
      ''
    else ref;  # IR expression — pass through as-is

  # ---------------------------------------------------------------------------
  # Options submodules
  # ---------------------------------------------------------------------------

  statementOptions = { ... }: {
    options = {
      sid           = mkOption { type = types.nullOr types.str;  default = null; };
      effect        = mkOption { type = types.enum [ "Allow" "Deny" ]; default = "Allow"; };
      actions       = mkOption { type = types.listOf types.str;  default = []; };
      notActions    = mkOption { type = types.listOf types.str;  default = []; };
      resources     = mkOption { type = types.listOf types.anything; default = []; };
      notResources  = mkOption { type = types.listOf types.anything; default = []; };
      principals    = mkOption { type = types.listOf (types.submodule principalOptions); default = []; };
      notPrincipals = mkOption { type = types.listOf (types.submodule principalOptions); default = []; };
      conditions    = mkOption { type = types.listOf (types.submodule conditionOptions); default = []; };
    };
  };

  principalOptions = { ... }: {
    options = {
      type        = mkOption { type = types.enum [ "AWS" "Service" "Federated" "*" ]; };
      identifiers = mkOption { type = types.listOf types.anything; };
    };
  };

  conditionOptions = { ... }: {
    options = {
      test     = mkOption { type = types.str; };
      variable = mkOption { type = types.str; };
      values   = mkOption { type = types.listOf types.str; };
    };
  };

  # data.aws_iam_policy_document
  policyDocumentOptions = { name, ... }: {
    options = {
      statements = mkOption {
        type        = types.listOf (types.submodule statementOptions);
        default     = [];
        description = "IAM policy statements.";
      };
      out.jsonRef = mkOption {
        type        = types.anything;
        readOnly    = true;
        default     = ir.mkData "aws_iam_policy_document" (tfName name) "json";
        description = ''
          IR reference to this document's rendered JSON.
          Pass to policyDocumentRef on iamUserPolicies, iamRolePolicies,
          or s3.<n>.bucketPolicy. Or use the name string shorthand instead.
        '';
      };
    };
  };

  # aws_s3_bucket + optional aws_s3_bucket_policy (nested — matches terraform)
  bucketPolicyOptions = { ... }: {
    options = {
      policyDocumentRef = mkOption {
        type        = types.either types.str types.anything;
        description = ''
          The policy to attach to this bucket.
          String: name of a policyDocuments entry in this provider.
          IR expression: use policyDocuments.<n>.out.jsonRef directly.
        '';
      };
    };
  };

  bucketOptions = { name, ... }: {
    options = {
      bucketName = mkOption {
        type        = types.str;
        description = "Globally unique S3 bucket name.";
      };

      # aws_s3_bucket_policy — nested under bucket, matching terraform's logical grouping
      bucketPolicy = mkOption {
        type        = types.nullOr (types.submodule bucketPolicyOptions);
        default     = null;
        description = ''
          Optional bucket resource policy. For external principals — other
          AWS accounts, CloudFront OAC, etc. In-cluster services use IAM
          user/role policies instead.
        '';
      };

      out = {
        # Category 1 — plain nix string, use directly in k8s manifests
        bucketName = mkOption {
          type        = types.str;
          readOnly    = true;
          default     = name;
          description = "Bucket name. Category 1 — reference directly in manifests.";
        };
        # Category 1/2 — IR expressions, use within same terraform root
        idRef = mkOption {
          type        = types.anything;
          readOnly    = true;
          default     = ir.mkRef "aws_s3_bucket" "s3_${name}" "id";
          description = "IR ref to bucket id. Use within same terraform root only.";
        };
        arnRef = mkOption {
          type        = types.anything;
          readOnly    = true;
          default     = ir.mkRef "aws_s3_bucket" "s3_${name}" "arn";
          description = "IR ref to bucket ARN. Use within same terraform root only.";
        };
      };
    };
  };

  # aws_iam_user — flat sibling of iamUserPolicies (matches terraform)
  iamUserOptions = { name, ... }: {
    options = {
      path = mkOption { type = types.str; default = "/"; };
      out = {
        nameRef = mkOption {
          type        = types.anything;
          readOnly    = true;
          default     = ir.mkRef "aws_iam_user" (tfName name) "name";
          description = "IR ref to user name. Pass to iamUserPolicies.<n>.user.";
        };
        arnRef = mkOption {
          type        = types.anything;
          readOnly    = true;
          default     = ir.mkRef "aws_iam_user" (tfName name) "arn";
          description = "IR ref to user ARN. Pass to vault.nix awsBackendRoles.";
        };
      };
    };
  };

  # aws_iam_user_policy — flat sibling of iamUsers (matches terraform)
  iamUserPolicyOptions = { ... }: {
    options = {
      user = mkOption {
        type        = types.anything;
        description = "IR ref to the IAM user name. Use iamUsers.<n>.out.nameRef.";
      };
      policyDocumentRef = mkOption {
        type        = types.either types.str types.anything;
        description = ''
          Policy to attach to this user.
          String: name of a policyDocuments entry in this provider.
          IR expression: use policyDocuments.<n>.out.jsonRef directly.
        '';
      };
    };
  };

  # aws_iam_role — flat sibling of iamRolePolicies (matches terraform)
  iamRoleOptions = { name, ... }: {
    options = {
      assumeRolePolicyRef = mkOption {
        type        = types.either types.str types.anything;
        description = ''
          Trust policy for this role.
          String: name of a policyDocuments entry containing a stsTrustStatement.
          IR expression: use policyDocuments.<n>.out.jsonRef directly.
        '';
      };
      path = mkOption { type = types.str; default = "/"; };
      out = {
        nameRef = mkOption {
          type        = types.anything;
          readOnly    = true;
          default     = ir.mkRef "aws_iam_role" (tfName name) "name";
          description = "IR ref to role name.";
        };
        arnRef = mkOption {
          type        = types.anything;
          readOnly    = true;
          default     = ir.mkRef "aws_iam_role" (tfName name) "arn";
          description = "IR ref to role ARN. Pass to vault.nix awsBackendRoles.";
        };
      };
    };
  };

  # aws_iam_role_policy — flat sibling of iamRoles (matches terraform)
  iamRolePolicyOptions = { ... }: {
    options = {
      role = mkOption {
        type        = types.anything;
        description = "IR ref to the IAM role id. Use iamRoles.<n>.out.nameRef.";
      };
      policyDocumentRef = mkOption {
        type        = types.either types.str types.anything;
        description = ''
          Policy to attach to this role.
          String: name of a policyDocuments entry in this provider.
          IR expression: use policyDocuments.<n>.out.jsonRef directly.
        '';
      };
    };
  };

  # aws_dynamodb_table
  dynamoOptions = { name, ... }: {
    options = {
      billingMode = mkOption {
        type    = types.enum [ "PAY_PER_REQUEST" "PROVISIONED" ];
        default = "PAY_PER_REQUEST";
      };
      hashKey    = mkOption { type = types.str; };
      rangeKey   = mkOption { type = types.nullOr types.str; default = null; };
      attributes = mkOption {
        type        = types.listOf (types.submodule {
          options = {
            name = mkOption { type = types.str; };
            type = mkOption { type = types.enum [ "S" "N" "B" ]; };
          };
        });
        description = "Attribute definitions. Only key attributes need declaring here.";
      };
      out = {
        tableName = mkOption {
          type        = types.str;
          readOnly    = true;
          default     = name;
          description = "Table name. Category 1 — reference directly in manifests.";
        };
        arnRef = mkOption {
          type        = types.anything;
          readOnly    = true;
          default     = ir.mkRef "aws_dynamodb_table" (tfName name) "arn";
          description = "IR ref to table ARN. Use within same terraform root only.";
        };
      };
    };
  };

  secretsEngineOptions = { name, ... }: {
    options = {
      enable                 = mkEnableOption "Vault AWS secrets engine";
      vaultMount             = mkOption { type = types.str; default = "aws-${name}"; };
      defaultLeaseTtlSeconds = mkOption { type = types.int; default = 3600; };
      maxLeaseTtlSeconds     = mkOption { type = types.int; default = 2592000; };
    };
  };

  providerOptions = { name, ... }: {
    options = {
      region = mkOption { type = types.str; };
      providerConfig = mkOption {
        type    = types.attrsOf types.anything;
        default = {};
        description = "Extra AWS provider config — assume_role, default_tags, endpoints, etc.";
      };
      secretsEngine = mkOption {
        type    = types.submodule secretsEngineOptions;
        default = {};
      };

      # Resource types — hierarchy matches terraform's own resource model:
      # - s3 buckets nest their bucket policy (aws_s3_bucket_policy)
      # - iam users and their policies are flat siblings
      # - iam roles and their policies are flat siblings
      policyDocuments = mkOption { type = types.attrsOf (types.submodule policyDocumentOptions); default = {}; };
      s3              = mkOption { type = types.attrsOf (types.submodule bucketOptions);         default = {}; };
      iamUsers        = mkOption { type = types.attrsOf (types.submodule iamUserOptions);        default = {}; };
      iamUserPolicies = mkOption { type = types.attrsOf (types.submodule iamUserPolicyOptions);  default = {}; };
      iamRoles        = mkOption { type = types.attrsOf (types.submodule iamRoleOptions);        default = {}; };
      iamRolePolicies = mkOption { type = types.attrsOf (types.submodule iamRolePolicyOptions);  default = {}; };
      dynamodb        = mkOption { type = types.attrsOf (types.submodule dynamoOptions);         default = {}; };

      out.ref = mkOption {
        type     = types.anything;
        readOnly = true;
        default  = ir.mkProviderRef "aws" name;
      };
    };
  };

  # ---------------------------------------------------------------------------
  # toIR helpers — 1:1 with terraform resource types
  # ---------------------------------------------------------------------------

  renderStatement = stmt:
    {}
    // optionalAttrs (stmt.sid          != null)   { sid            = stmt.sid; }
    // optionalAttrs (stmt.effect       != "Allow") { effect        = stmt.effect; }
    // optionalAttrs (stmt.actions      != [])      { actions       = stmt.actions; }
    // optionalAttrs (stmt.notActions   != [])      { not_actions   = stmt.notActions; }
    // optionalAttrs (stmt.resources    != [])      { resources     = stmt.resources; }
    // optionalAttrs (stmt.notResources != [])      { not_resources = stmt.notResources; }
    // optionalAttrs (stmt.principals   != []) {
         principals     = map (p: { inherit (p) type identifiers; }) stmt.principals; }
    // optionalAttrs (stmt.notPrincipals != []) {
         not_principals = map (p: { inherit (p) type identifiers; }) stmt.notPrincipals; }
    // optionalAttrs (stmt.conditions   != []) {
         condition = map (c: { inherit (c) test variable values; }) stmt.conditions; };

  policyDocumentToIR = name: cfg:
    ir.mkDataSource {
      type   = "aws_iam_policy_document";
      name   = tfName name;
      config.statement = map renderStatement cfg.statements;
    };

  bucketToIR = providerCfg: name: cfg: providerRef:
    let
      rn     = "s3_${name}";
      idRef  = ir.mkRef "aws_s3_bucket" rn "id";

      bucket = ir.mkResource {
        type    = "aws_s3_bucket";
        name    = rn;
        config  = { bucket = cfg.bucketName; provider = providerRef; };
        outputs = {
          "s3_${name}_id"   = ir.mkRef "aws_s3_bucket" rn "id";
          "s3_${name}_arn"  = ir.mkRef "aws_s3_bucket" rn "arn";
          "s3_${name}_name" = cfg.bucketName;
        };
      };

      # aws_s3_bucket_policy nested under the bucket — matches terraform's grouping
      policyResources = lib.optional (cfg.bucketPolicy != null)
        (ir.mkResource {
          type   = "aws_s3_bucket_policy";
          name   = "${rn}_policy";
          config = {
            bucket   = idRef;
            policy   = resolvePolicy providerCfg cfg.bucketPolicy.policyDocumentRef;
            provider = providerRef;
          };
        });

    in [ bucket ] ++ policyResources;

  iamUserToIR = name: cfg: providerRef:
    ir.mkResource {
      type    = "aws_iam_user";
      name    = tfName name;
      config  = { name = name; path = cfg.path; provider = providerRef; };
      outputs = {
        "${tfName name}_arn"  = ir.mkRef "aws_iam_user" (tfName name) "arn";
        "${tfName name}_name" = ir.mkRef "aws_iam_user" (tfName name) "name";
      };
    };

  iamUserPolicyToIR = providerCfg: name: cfg: providerRef:
    ir.mkResource {
      type   = "aws_iam_user_policy";
      name   = tfName name;
      config = {
        name     = name;
        user     = cfg.user;
        policy   = resolvePolicy providerCfg cfg.policyDocumentRef;
        provider = providerRef;
      };
    };

  iamRoleToIR = providerCfg: name: cfg: providerRef:
    ir.mkResource {
      type    = "aws_iam_role";
      name    = tfName name;
      config  = {
        name               = name;
        assume_role_policy = resolvePolicy providerCfg cfg.assumeRolePolicyRef;
        path               = cfg.path;
        provider           = providerRef;
      };
      outputs = {
        "${tfName name}_arn"  = ir.mkRef "aws_iam_role" (tfName name) "arn";
        "${tfName name}_name" = ir.mkRef "aws_iam_role" (tfName name) "name";
      };
    };

  iamRolePolicyToIR = providerCfg: name: cfg: providerRef:
    ir.mkResource {
      type   = "aws_iam_role_policy";
      name   = tfName name;
      config = {
        name     = name;
        role     = cfg.role;
        policy   = resolvePolicy providerCfg cfg.policyDocumentRef;
        provider = providerRef;
      };
    };

  dynamoToIR = name: cfg: providerRef:
    ir.mkResource {
      type    = "aws_dynamodb_table";
      name    = tfName name;
      config  = {
        name         = name;
        billing_mode = cfg.billingMode;
        hash_key     = cfg.hashKey;
        provider     = providerRef;
        attribute    = map (a: { inherit (a) name type; }) cfg.attributes;
      }
      // optionalAttrs (cfg.rangeKey != null) { range_key = cfg.rangeKey; };
      outputs = {
        "${tfName name}_arn"  = ir.mkRef "aws_dynamodb_table" (tfName name) "arn";
        "${tfName name}_name" = name;
      };
    };

  secretsEngineToIR = providerName: cfg:
    if !cfg.secretsEngine.enable then []
    else [(ir.mkResource {
      type   = "vault_aws_secret_backend";
      name   = tfName cfg.secretsEngine.vaultMount;
      config = {
        path                      = cfg.secretsEngine.vaultMount;
        region                    = cfg.region;
        access_key                = ir.mkVar "aws_${providerName}_engine_access_key_id";
        secret_key                = ir.mkVar "aws_${providerName}_engine_secret_access_key";
        default_lease_ttl_seconds = cfg.secretsEngine.defaultLeaseTtlSeconds;
        max_lease_ttl_seconds     = cfg.secretsEngine.maxLeaseTtlSeconds;
      };
    })];

  secretsEngineVariables = providerName: cfg:
    if !cfg.secretsEngine.enable then {}
    else {
      "aws_${providerName}_engine_access_key_id" = {
        type = "string"; sensitive = true;
        description = "Access key ID for Vault AWS secrets engine (provider: ${providerName}).";
      };
      "aws_${providerName}_engine_secret_access_key" = {
        type = "string"; sensitive = true;
        description = "Secret access key for Vault AWS secrets engine (provider: ${providerName}).";
      };
    };

in
{
  options = { ... }: {
    options.providers = mkOption {
      type        = types.attrsOf (types.submodule providerOptions);
      default     = {};
      description = ''
        Named AWS provider configurations.
        Resource hierarchy matches terraform's own model:
          s3.<n>.bucketPolicy     — nested (aws_s3_bucket_policy is logically part of the bucket)
          iamUsers + iamUserPolicies — flat siblings (independent terraform resources)
          iamRoles + iamRolePolicies — flat siblings (independent terraform resources)
      '';
    };
  };

  toIR = awsCfg:
    let
      resources = flatten (mapAttrsToList (providerName: providerCfg:
        let providerRef = ir.mkProviderRef "aws" providerName;
        in flatten [
          (secretsEngineToIR providerName providerCfg)
          (mapAttrsToList policyDocumentToIR providerCfg.policyDocuments)
          # bucketToIR needs providerCfg for resolvePolicy on bucketPolicy
          (flatten (mapAttrsToList (n: c: bucketToIR         providerCfg n c providerRef) providerCfg.s3))
          (mapAttrsToList          (n: c: iamUserToIR               n c providerRef)      providerCfg.iamUsers)
          (mapAttrsToList          (n: c: iamUserPolicyToIR providerCfg n c providerRef)  providerCfg.iamUserPolicies)
          (mapAttrsToList          (n: c: iamRoleToIR       providerCfg n c providerRef)  providerCfg.iamRoles)
          (mapAttrsToList          (n: c: iamRolePolicyToIR providerCfg n c providerRef)  providerCfg.iamRolePolicies)
          (mapAttrsToList          (n: c: dynamoToIR               n c providerRef)      providerCfg.dynamodb)
        ]
      ) awsCfg.providers);

    in {
      resources = resources;
      outputs   = irLib.liftOutputs resources;

      providers = listToAttrs (mapAttrsToList (name: cfg:
        nameValuePair name (
          { providerType = "aws"; region = cfg.region; }
          // cfg.providerConfig
        )
      ) awsCfg.providers);

      variables = mergeAll (mapAttrsToList
        (n: cfg: secretsEngineVariables n cfg)
        awsCfg.providers);

      remoteState = [];
    };

  inherit s3Statement dynamoStatement stsTrustStatement;
  inherit s3Actions dynamoActions;
}
