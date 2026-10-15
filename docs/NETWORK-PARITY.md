# Networking parity: implementation and provider differences

Updated 2026-10-15 for version 0.6.0. This closes the feasible metadata work in
the 14 requested networking rows. **Full AWS semantic parity and live Tencent
validation are not established.** The comparison uses the original AWS checkout's
EC2 models, collectors and EXPOSE analysis; its revision and registry hash remain
recorded in [the audit](aws-parity-audit.json).

All additional inventory calls are fixed, allowlisted `Describe*` operations.
Collection and offline analysis remain read-only. No cloud resources, networking
rules or bindings are modified. No function is invoked, health probe initiated,
VPN connection secret retrieved, or workload definition downloaded.

## Closure of the requested rows

| Tencent counterpart | Implemented metadata and reconciliation | Provider difference or evidence limit retained |
|---|---|---|
| VPC security groups | Account/region scope; reverse group references; association counts; same-region identifier collisions across collected owners suppress the reference edge and mark analysis partial | Tencent SGs are regional resources. The rule selector supplies an SG ID without an owner UIN; missing or ambiguous owners cannot be recovered from an AppId or a VPC guess. Effective traffic authorization remains unevaluated |
| VPC subnets | Native `IsDefault`, zone, creation/capacity, stack, broadcast/SNAT, IPv4/IPv6, route/ACL associations; unique collected default within VPC/zone; explicit subnet-to-VPC CIDR containment | `IsDefault` is retained as Tencent's flag, without asserting AWS `DefaultForAz`. The audited response has no AWS launch-time public/customer-owned IP assignment, IPv6-on-creation or subnet lifecycle state fields |
| Traditional CLB | Native listener-wide bindings, certificates, health settings/status, private and public backend addresses; ENI IDs; unknown types preserved as bindings/address targets; scope-checked exposure where inventory corroborates identity | Classic ELB hosted-zone IDs, AWS policies and account-specific runtime semantics are not synthesized. Unknown provider target identities remain unresolved; Tencent does not offer every modern target type on traditional CLB |
| Modern CLB | Native `DescribeTargets` bindings for CVM/ENI/NAT and other returned types; SCF name/namespace/version-or-alias metadata; expanded LB/listener/rule fields; cross-VPC/region 2.0 metadata queried per listener or exact L7 rule; legacy 1.0 target-region/VPC correspondence | Arbitrary SRV/EVM/GLOBALROUTE or on-premises IPs with no collected identity remain configured metadata. SCF inventory is matched in the same account/region/namespace; function code/environment are excluded. AWS-specific attributes remain provider differences |
| CLB configured exposure | Paths to collected CVM, ENI, NAT/HAVIP, scoped IP and SCF resources; cross-VPC/region paths require exact frontend evidence plus unique collected ENI/IP/VPC identity; legacy CVM IDs require explicit backend region/VPC and unique inventory | EXPOSE describes configured forwarding. It proves no public reachability, firewall passage, function execution or effective access. Conflicting, inaccessible or ambiguous backends remain partial |
| VPC network ACLs | Native three-/five-field policy inventory; explicit subnet association reconciliation; contradictory account/region/VPC, ACL IDs or explicit no-ACL reports suppress active links and retain reported associations | The audited native ACL schema has no AWS default-ACL flag or AWS association ID. An unbound subnet does not cause a fabricated default ACL or inferred default allow/deny result |
| VPC ENIs | Native lifecycle, MAC, attachment time/index/account namespace, CDC, ENI/attachment type, IPv4/IPv6 and retained-IP resource metadata; non-CVM attachment child records; CVM links only when scoped inventory corroborates the attachment | `Business=eks/hai` is not relabeled as CVM. `ResourceId` identifies IP retention, not an attachment. Opaque `InstanceAccountId` is not converted into UIN. AWS requester-managed/source-destination-check/private-DNS fields are not invented; workload definitions remain excluded |
| Cloud Connect Network | Owned CCNs plus attachment discovery filtered to each collected local VPC; explicit `CcnUin` preserves a foreign CCN owner even when its full inventory is inaccessible; network CIDRs link to contained local subnet CIDRs; shared owner evidence can resolve CCN route next hops | Discovery is bounded to authorized, visible local attachments. It cannot enumerate all foreign shares. CCN attaches whole networks; CIDR inclusion does not create AWS transit attachment subnets or prove routing |
| VPC | Native default/DHCP/DNS/multicast/publication settings; primary/auxiliary/provider IPv4/IPv6 CIDRs and subnet containment | The audited responses do not expose AWS tenancy, VPC lifecycle state or CIDR association ID/state/message. Creation time, provider CIDR role and inclusion are retained without assigning those AWS meanings |
| Private Link | Native endpoint-service UIN allowlists and auto-accept metadata; independently scoped IP-family/service types; unique collected endpoint ENI/address match; enabled Private DNS A/AAAA record matches require explicit zone-to-VPC binding; native endpoint route links; full GWLB/group/backend/reported-health metadata | The service allowlist is not an AWS endpoint IAM policy. Observed DNS records do not establish `PrivateDnsEnabled`, resolver precedence or runtime resolution. No AWS requester-managed or gateway-endpoint route association is inferred |
| VPC route tables | Native main/subnet associations, enabled flag and USER/NETD/CCN origin labels; private NAT, local/CDC, VPN, Direct Connect, HAVIP and GWLB endpoint identities; scoped IP-to-ENI/CVM next hops; explicit owner reconciliation for shared CCNs | Disabled does not mean AWS `blackhole`; native route type does not assert an AWS route origin. Sentinel `GatewayId=0` remains a provider egress value. Missing association IDs, unknown types and effective route selection are not guessed |
| VPC peering | Native pending/active/rejected/deleted/failed/expired/isolated states, endpoint UIN/region, bandwidth/billing/QoS; collected versus reference-only endpoint visibility; CIDRs only from collected endpoint VPCs | The audited API has no AWS DNS-resolution/ClassicLink options or detailed status-message counterpart. Inaccessible remote CIDRs and association state cannot be reconstructed from peering names |
| Tencent public egress | Collected public-address/EIP/NAT bindings, native gateways and route next hops; `INTRANAT` is a private NAT identity distinct from public NAT | Tencent's model is represented directly. No AWS-style IGW resource, attachment state or internet reachability is asserted |
| VPC EIP | Typed HAVIP and DHCPIP bindings in addition to CVM/NAT/ENI/CLB; legacy and current elastic IPv6, ordinary IPv6 and high-quality elastic IPv6; eip/eipv6 identities; explicit ENI/private-address reconciliation with contradiction checks; unknown target types remain visible | AWS allocation/association/domain fields have no asserted native equivalence. Public-IP equality alone never resolves a target. Denied/unsupported APIs and unknown future types retain partial coverage |

## API and graph behavior

The permission-review inventory now contains **233 exact read operations**, up
from 216. The 17 additions are:

- VPC: `DescribeSecurityGroupReferences`,
  `DescribeSecurityGroupAssociationStatistics`, `DescribeIp6Addresses`,
  `DescribeIPv6Addresses`, `DescribeDhcpIps`, `DescribeLocalGateway`,
  `DescribePrivateNatGateways`, `DescribeHaVips`, `DescribeVpnGateways`,
  `DescribeDirectConnectGateways`, `DescribeVpcEndPointServiceWhiteList`.
- CLB: `DescribeTargets`, `DescribeCrossTargets`.
- GWLB (`2024-09-06`): `DescribeGatewayLoadBalancers`, `DescribeTargetGroups`,
  `DescribeTargetGroupInstances`, `DescribeTargetGroupInstanceStatus`.

`DescribeCcnAttachedInstances` was already allowlisted; shared discovery adds
local-VPC filters and validates the returned network and root owners. API
availability and permissions remain account/region specific. Failures are recorded
per operation and parent; they never become a successful empty inventory.

The `gwlb` service participates in the existing service/region plan. It is included
in an unrestricted collection or can be selected explicitly. RMS product discovery
must actually return a matching product; the collector does not guess a region
from CVM or silently cross an explicit region restriction.

```bash
./landscape/local.sh sync --profile default --regions eu-frankfurt \
  --services vpc,clb,gwlb,cvm,scf,privatedns
```

Use the existing multi-profile/project configuration for additional environments.
Cross-account corroboration uses only inventories collected through those verified
profiles. It never logs in to a newly discovered account. Missing backend inventory
can therefore leave a valid configuration unresolved.

Offline `analyze` recomputes the network reconciliation and exposure links. Derived
links are replaced, and stale owner/address evidence cannot preserve a prior
exposure result. `ReconcileNetworkMetadata` reports ambiguous owners, conflicting
associations, unresolved SCF/cross-target identities and unknown EIP target types.

All resource kinds use bundled official assets. The official archive contains no
dedicated GWLB product symbol; GWLB uses its Cloud Load Balancer asset. VPN and
Direct Connect use their service-specific official symbols. All 896 archive SVGs
and the official Tencent Cloud wordmark remain byte-verified.

## Primary references

- [Tencent VPC data structures](https://cloud.tencent.com/document/product/215/15824)
  and the official installed VPC SDK models.
- [Tencent CLB data structures](https://cloud.tencent.com/document/api/214/30694)
  and [cross-target query](https://cloud.tencent.com/document/api/214/65902).
- [SCF binding restrictions and semantics](https://intl.cloud.tencent.com/zh/document/product/214/39790),
  [cross-region 1.0](https://cloud.tencent.com/document/product/214/12014), and
  [cross-region 2.0](https://cloud.tencent.com/document/product/214/48180).
- [IPv6 inventory and filters](https://cloud.tencent.com/document/product/215/113677)
  and [private NAT inventory](https://cloud.tencent.com/document/api/215/107891).
- [GWLB API catalog](https://cloud.tencent.com/document/product/1782/111711)
  and [GWLB data structures](https://cloud.tencent.com/document/product/1782/111701).

The official installed Tencent SDK models were also checked for exact request,
response, ownership and field-type contracts. These checks and the offline fixtures
do not substitute for authenticated live validation.
