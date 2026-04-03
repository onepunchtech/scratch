{ lib }:
let
  inherit (lib)
    foldl' recursiveUpdate mapAttrs mapAttrsToList
    listToAttrs nameValuePair optionalAttrs;

  mergeAll = foldl' recursiveUpdate {};

  # ---------------------------------------------------------------------------
  # renderExpr :: expression | scalar → terraform value
  # ---------------------------------------------------------------------------

  renderExpr = expr:
    if      !(builtins.isAttrs expr)           then expr
    else if !(expr ? __type)                   then expr
    else if expr.__type == "var"               then "\${var.${expr.var}}"
    else if expr.__type == "ref"               then
      let r = expr.ref;
      in "\${${r.type}.${r.name}.${r.attr}}"
    else if expr.__type == "data"              then
      let d = expr.data;
      in "\${data.${d.type}.${d.name}.${d.attr}}"
    else if expr.__type == "remoteRef"         then
      let r = expr.remoteRef;
      in "\${data.terraform_remote_state.${r.phase}.outputs.${r.outputKey}}"
    else if expr.__type == "providerRef"       then
      let p = expr.providerRef;
      in "${p.providerType}.${p.alias}"
    else if expr.__type == "concat"            then
      lib.concatStrings (map renderExpr expr.parts)
    else throw "toTerranix.renderExpr: unknown __type '${expr.__type}'";

  renderValue = v:
    if      builtins.isAttrs v && (v ? __type) then renderExpr  v
    else if builtins.isAttrs v                  then renderAttrs v
    else if builtins.isList  v                  then map renderValue v
    else                                             v;

  renderAttrs = attrs: mapAttrs (_: renderValue) attrs;

  # ---------------------------------------------------------------------------
  # renderProviders :: { providerName → providerCfg } → terranix provider attrset
  #
  # Providers are grouped by providerType (aws, vault, auth0).
  # When a providerType has only one entry → single block, no alias field.
  # When a providerType has multiple entries → list of blocks, each with alias.
  # The alias value is the attrName the user gave in aws.providers.
  # ---------------------------------------------------------------------------

  renderProviders = providers:
    let
      # Group entries by providerType
      # providers attrset shape: { <alias> → { providerType, region, ... } }
      byType = foldl' (acc: entry:
        let
          t    = entry.providerType;
          rest = builtins.removeAttrs entry [ "providerType" ];
        in acc // { ${t} = (acc.${t} or []) ++ [ rest ]; }
      ) {} (mapAttrsToList (alias: cfg:
        cfg // { providerType = cfg.providerType or alias; inherit alias; }
      ) providers);

    in mapAttrs (providerType: entries:
      if builtins.length entries == 1
      then
        # Single entry — emit plain block, no alias needed
        renderAttrs (builtins.removeAttrs (builtins.head entries) [ "alias" "providerType" ])
      else
        # Multiple entries — emit list, each with alias
        map (entry: renderAttrs entry) entries
    ) byType;

  # Known provider sources and versions — derived from ir.providers
  knownProviders = {
    aws   = { source = "hashicorp/aws";   version = "~> 5.0"; };
    vault = { source = "hashicorp/vault"; version = "~> 3.0"; };
    auth0 = { source = "auth0/auth0";     version = "~> 1.0"; };
  };

  deriveRequiredProviders = providers:
    let
      providerTypes = lib.unique (lib.mapAttrsToList (_: p: p.providerType) providers);
    in
      lib.filterAttrs (name: _: builtins.elem name providerTypes) knownProviders;

in

# ---------------------------------------------------------------------------
# toTerranix :: IR → terranix-compatible attrset
#
# providers are part of ir — no separate argument needed.
# Pure function. Test with: nix eval --expr '(import ./toTerranix.nix { inherit lib; }) myIR'
# ---------------------------------------------------------------------------

ir:

mergeAll [

  # terraform block — required_providers derived from ir.providers
  {
    terraform = {
      required_providers = deriveRequiredProviders ir.providers;
      backend.http       = {};
    };
  }

  (mergeAll (map (r:
    if r.isDataSource
    then { data.${r.type}.${r.name}     = renderAttrs r.config; }
    else { resource.${r.type}.${r.name} = renderAttrs r.config; }
  ) ir.resources))

  (optionalAttrs (ir.outputs != {}) {
    output = mapAttrs (_: o: {
      value = renderExpr o.value;
    }
    // optionalAttrs (o.description != "") { description = o.description; }
    // optionalAttrs  o.sensitive          { sensitive   = true; }
    ) ir.outputs;
  })

  (optionalAttrs (ir.remoteState != []) {
    data.terraform_remote_state = listToAttrs (map (rs:
      nameValuePair rs.phase {
        backend = "http";
        config  = {
          address        = "\${var.gitlab_url}/api/v4/projects/\${var.gitlab_project_id}/terraform/state/${rs.stateKey}";
          lock_address   = "\${var.gitlab_url}/api/v4/projects/\${var.gitlab_project_id}/terraform/state/${rs.stateKey}/lock";
          unlock_address = "\${var.gitlab_url}/api/v4/projects/\${var.gitlab_project_id}/terraform/state/${rs.stateKey}/lock";
          username       = "gitlab-ci-token";
          password       = "\${var.gitlab_token}";
          lock_method    = "POST";
          unlock_method  = "DELETE";
          retry_wait_min = 5;
        };
      }
    ) ir.remoteState);
  })

  (optionalAttrs (ir.providers != {}) {
    provider = renderProviders ir.providers;
  })

  (optionalAttrs (ir.variables != {}) {
    variable = mapAttrs (_: v:
      { type = v.type; }
      // optionalAttrs (v.description != "")  { description = v.description; }
      // optionalAttrs (v.default     != null) { default     = v.default; }
      // optionalAttrs  v.sensitive            { sensitive   = true; }
    ) ir.variables;
  })

]
