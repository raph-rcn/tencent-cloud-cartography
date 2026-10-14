# Configuration authorization analysis

The engine evaluates collected configuration offline. An `allowed` result means
the supported, collected policy gates allow the declared action and scope. It
**does not prove effective access, an exploitable finding or successful execution**.
Effective access remains `unknown`; no token is issued, role assumed, object read,
secret retrieved, SQL queried or command executed.

## Named COS access

`cos.authorizationdecision` joins each enriched CAM user/role with each enriched
COS bucket for GetObject, PutObject, DeleteObject, GetBucket (listing), GetBucketACL
and PutBucketACL. Object-prefix scopes come from supported policy expressions;
bucket-root aliases do not become object reads. Each result links its principal,
bucket and supporting statements/ACL grants.

- Same-account identity and applicable named resource grants are combined as a
  union. Cross-account access requires both caller and resource authorization.
- Account-root resource grants delegate through the caller's account; they are
  not direct grants to every child identity. Group membership requires collected
  membership evidence. UIN, UID/AppId and creator identifiers are not interchangeable.
- Matching explicit denies take precedence. Missing potential deny evidence stays
  unknown. Collected permission boundaries constrain identity grants; missing/null/
  denied boundary responses do not establish that no boundary exists.
- A resource-only grant with an implicit boundary deny stays unknown: Tencent's
  documented boundary intersection does not establish that particular interaction.
- Anonymous access is a separate unsigned route. An anonymous deny does not deny a
  signed IAM grant. Matching existing public decisions are linked as alternative
  unsigned analyses, with their own evidence and result.
- Object ACLs are not collected. Potential additional object grants remain unknown;
  bucket ACL object permission requires an unresolved inheritance condition.
  A proven same-account IAM grant is not suppressed merely by missing additional
  object grants. Missing potential deny inputs still prevent an allow conclusion.
- Unsupported principals, policy/resource syntax, owner conflicts and uncollected
  session constraints remain explicit uncertainties.

References: [COS authorization routes](https://intl.cloud.tencent.com/zh/document/product/436/35240),
[COS principals](https://intl.cloud.tencent.com/zh/document/product/436/18023),
[CAM cross-account evaluation](https://intl.cloud.tencent.com/zh/document/product/598/10605),
[permission boundaries](https://cloud.tencent.com/document/product/598/48770).

## Role trust and permission paths

`cam.assumptiondecision` intersects caller identity permission for `sts:AssumeRole`,
the collected caller boundary, and the target role's collected trust policy.
Role ID/ARN and documented roleName resource forms are evaluated together so a deny
on an alias cannot be bypassed. Caller identity restrictions using
`qcs:assume_principal_arn` are derived from collected identity; operator context
cannot supply a different caller.

Named CAM callers are distinct from service and federated principals. External ID,
MFA and session restrictions are unresolved when not safely evaluated. Missing trust
collection remains unknown. Self-assumption is included and cycles are bounded.

`cam.authorizationpath` retains one shortest witness per starting user/role,
permission endpoint and decision class (allowed, conditional, unknown). All source
assumption edges remain in the full graph. Paths can lead to the joined COS decisions
and supported secret/PassRole/database/TAT/TIC identity-policy targets. Legacy
identity-only COS matches cannot bypass a joined COS resource deny.

These are configuration paths. They do not enumerate every alternative path or solve
joint satisfiability of conditions across hops. Effective role assumption, session
permission propagation, workload identity and actual data/command access are unverified.

References: [role trust and caller restrictions](https://cloud.tencent.com/document/product/598/19381),
[caller AssumeRole permission](https://intl.cloud.tencent.com/zh/document/product/598/19422),
[role principal types](https://cloud.tencent.com/document/product/598/19419).

## Request context and offline use

Opening the viewer never runs analysis or contacts Tencent Cloud. `sync` analyzes
its collected snapshot; `analyze` recalculates a saved snapshot without cloud calls:

```bash
# Preserve the input; select the analyzed output explicitly in the viewer.
tencent-cloud-cartography analyze --input inventory.json --output analyzed.json

tencent-cloud-cartography analyze --input inventory.json --output analyzed.json \
  --context request-context.json --analysis-limit 25000
tencent-cloud-cartography serve --input analyzed.json
```

Example nonsecret context (declares a hypothetical request, not a live observation):

```json
{
  "qcs:ip": "192.0.2.10",
  "qcs:current_time": "2026-10-14T12:00:00Z",
  "cos:prefix": "docs/",
  "cos:secure-transport": true
}
```

Accepted context keys are `qcs:ip`, `qcs:current_time`, `cos:prefix`, `cos:versionid`,
`cos:x-cos-storage-class`, `cos:x-cos-acl`, `cos:secure-transport`. Context is retained
in generated decisions; provide only approved nonsecret metadata. Files over 16 KiB,
duplicate keys, credentials, tokens, external IDs, identity overrides and session
policies are rejected. Time must include a timezone; IP must be one address.
The engine never guesses the current time or reads environment values as context.

Supported operators cover IP equality/inequality with network matching, UTC date
comparisons, string equality/inequality (including supported ignore-case forms),
and boolean secure transport. Values are ORed; clauses and operators are ANDed.
Missing attributes and unsupported operators stay unresolved. Case, wildcard and
provider-specific resource semantics are conservatively evaluated.

Analysis defaults to **25,000 generated decisions per phase**. `sync` and `analyze`
accept `--analysis-limit` from 1 to 1,000,000. A breached limit produces visible
`AuthorizationDecisionLimitExceeded` partial coverage and preserves source nodes
and relationships. Raising the limit increases runtime and memory use. The limit
bounds generated output; underlying policy evaluation still depends on input size.
Reanalysis replaces only generated results and preserves the source graph.

References: [CAM conditions](https://cloud.tencent.com/document/product/598/10608),
[COS conditions](https://cloud.tencent.com/document/product/436/71307).
