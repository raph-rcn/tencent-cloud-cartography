# Authentication and scan sessions

Collection stays **read-only against Tencent Cloud resources and metadata-only**.
Authentication can issue temporary sessions and refresh the selected profile's
local credential cache. It does not create resources, attach policies, grant
permissions, or retrieve workload/secret contents. JSON and Neo4j publication
write the locally collected inventory. The viewer makes no Tencent API calls.

## Supported profiles

Every Cloud API, COS, international CVM and legacy TIC collector shares one
credential resolver and one verified session per profile. Use a current TCCLI;
the native authentication/signing integration is tested against **3.1.181.1**.
The application requires Python 3.11+; TCCLI's separate interpreter requires
Python 3.10+. TCCLI and the application's international SDK remain isolated.

| Source | Resolution and renewal |
|---|---|
| Named/static TCCLI profile | `~/.tccli/NAME.credential` supplies the complete credential; no environment merging |
| Environment | Only `default`, when its credential file is absent; requires a complete SecretId/SecretKey pair, with optional session token |
| Browser/OAuth | Uses an existing `tccli auth login` profile; refreshes native access tokens and temporary credentials as needed |
| Tencent Cloud SSO | Uses an existing `tccli sso login` profile; renews the configured account/role while its login session remains valid |
| Configured role | Requires both `role-arn` and `role-session-name` in that profile, or the corresponding complete environment configuration; uses STS `AssumeRole` and renews the session |
| Explicit CVM role | Only a profile with `type: cvm-role` permits the official instance credential provider; there is no implicit IMDS fallback |
| Explicit TKE OIDC | When no default credential file/role takes precedence, all four documented TKE environment fields are required; exchanges the local identity token using STS `AssumeRoleWithWebIdentity` |

A missing named profile fails. An invalid/incomplete profile fails even if
environment credentials exist. A configured role cannot silently fall back to
its source identity. Organization membership does not trigger login, account
switching, or automatic member-role assumption. External credential-process
plugins, custom auth endpoints and arbitrary role discovery are not supported.

## Sign in locally

Run the appropriate login command yourself before collecting. Cartography never
opens a login browser or prompts for keys during a scan.

```bash
# Tencent browser login
tccli auth login --profile client-a

# Existing SSO profile (first configure its organization access URL with TCCLI)
tccli sso login --profile client-b

tencent-cloud-cartography sync --profile client-a --profile client-b --regions eu-frankfurt
```

Use your organization's existing read-only access. A configured role may require
STS permission to assume that specific role; this does not imply its source
credentials can read the inventory. Never paste keys into chat, commit credential
files, or put them in command arguments. Perform independent TCCLI login/logout
and profile edits between scans.

The launcher normally identifies TCCLI's interpreter from its Python shebang
(including Homebrew, pipx and normal pip/uv installations). For a custom shell
wrapper or packaged launcher, specify its interpreter explicitly:

```bash
tencent-cloud-cartography sync --profile client-a --regions eu-frankfurt \
  --tccli /path/to/tccli --tccli-python /path/to/tccli-environment/bin/python
```

The bridge uses the official CommonClient from that TCCLI installation, pinned
service versions and fixed verified-HTTPS Tencent endpoints. It bypasses the
CLI command logger and provider differences between generated commands and the
COS plugin. COS bucket listing now uses the official SDK's structured metadata
response and follows `NextMarker` pagination; no object listing occurs.

## Refresh and account isolation

- Before each request, the resolver checks for a changed source or a credential
  approaching expiry (five-minute renewal window). Manually supplied temporary
  credentials cannot be renewed without a renewable source; expired sessions
  require local reauthentication/replacement.
- Each new credential generation is checked with STS `GetCallerIdentity` before
  any collector uses it. Account, source principal, identity type, ARN and user
  identity stay bound. Only the documented CAMRole session-name suffix may
  change; role ID remains fixed. SSO/configured-role target accounts are checked.
- Recognized expired-token responses permit one forced refresh and one replay.
  Permission denial never selects another credential source. Signature-clock
  errors are not treated as an invitation to keep refreshing.
- Identity changes or unverifiable renewal permanently fail that profile's scan
  attempt, even if the profile later changes back. The final identity check is
  retained. Its account inventory is discarded while other healthy accounts
  remain publishable.
- If all accounts fail, previous inventory stays intact and the private attempt
  report records the failure. Existing `sync` exit codes remain 0/2/1 for complete,
  usable-partial, and unusable/failed collection.

Private profile outcomes record the provider, authentication state, verified
generation count, observed credential changes, safe error code and local login
command. The coverage overview displays provider, state, renewal count and login
guidance; terminal failures include the safe code and applicable login command. An older snapshot says authentication was not recorded. An expired
SSO login requires `tccli sso login --profile NAME`; browser login requires
`tccli auth login --profile NAME`. A failed refresh is distinct from an expired
login and never proves that an account has no resources.

## Credential handling

Credentials pass to the isolated runtime through private stdin/stdout pipes,
never newly constructed command arguments or temporary credential files. SDK
collectors receive the same frozen in-memory credential. Native stdout/stderr,
raw provider errors and credential-bearing SDK debug output are suppressed.
Inventory snapshots, coverage reports, graphs and logs never include session
tokens, SecretKeys, OAuth/SSO tokens, assertions or private credential fingerprints.

Native OAuth/SSO cache updates retain TCCLI's schema, preserve explicitly
configured roles, serialize Cartography refreshes, use atomic `0600` replacement,
and remove temporary files. Role/CVM/OIDC issued credentials remain in memory.
OAuth helper calls are hardened to require verified TLS, bounded timeouts and
no redirects. No refresh request uses an endpoint taken from a credential file.

## Validation boundary

Tests exercise the installed native TCCLI OAuth/SSO helpers, cache writes, STS
role exchange and SDK signing with offline HTTP fixtures and blocked sockets.
They cover renewal during a long scan, identity changes/reversions, a single
expired-token replay, strict source precedence, denied permissions, credential
redaction and healthy-account preservation. Live login, organization access,
role trust and Frankfurt permissions remain environment-specific and unverified.

Official references: [browser login](https://cloud.tencent.com/document/product/440/111345),
[SSO login and renewal](https://cloud.tencent.cn/document/product/440/132374),
[TCCLI providers](https://github.com/TencentCloud/tencentcloud-cli/blob/master/README.md),
[caller identity](https://intl.cloud.tencent.com/zh/document/product/1150/49453),
[COS bucket pagination](https://intl.cloud.tencent.com/zh/document/api/436/8291).
