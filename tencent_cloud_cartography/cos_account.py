"""Account views of collected bucket controls, without fabricating an S3-style switch."""

from .model import stable_id

SOURCE = "analysis.cos-account-controls"


def analyze(graph):
    stale = {nid for nid, n in graph.nodes.items() if n["kind"] == "cos.accountaccesssummary"}
    graph.nodes = {nid: n for nid, n in graph.nodes.items() if nid not in stale}
    graph.edges = {
        eid: e
        for eid, e in graph.edges.items()
        if e["source"] not in stale and e["target"] not in stale
    }
    graph.coverage = [r for r in graph.coverage if r.get("action") != "SummarizeCosAccountControls"]
    for account in graph.accounts:
        buckets = [
            n
            for n in graph.nodes.values()
            if n["kind"] == "cos.bucket" and n["account"] == account and n["status"] == "enriched"
        ]
        records = [
            r
            for r in graph.coverage
            if r.get("account") == account
            and r.get("service") == "cos"
            and r.get("action") == "list_buckets"
        ]
        if not buckets and not records:
            continue
        decisions = [
            n
            for n in graph.nodes.values()
            if n["kind"] == "cos.publicaccessdecision" and n["account"] == account
        ]
        nid = graph.add(
            account,
            "global",
            "cos.accountaccesssummary",
            stable_id(account, "cos-account-controls"),
            "Selected bucket access controls",
            source=SOURCE,
        )
        graph.nodes[nid]["properties"].update(
            evaluation_scope="selected_region_bucket_configuration",
            bucket_count=len(buckets),
            decision_count=len(decisions),
            incomplete_decision_count=sum(
                n["properties"].get("decision") == "incomplete" for n in decisions
            ),
            bucket_listing_complete_for_selected_regions=bool(records)
            and all(r["status"] in ("complete", "empty") for r in records),
            account_level_block_configuration="no_equivalent_audited_api",
            global_block_state_verified=False,
            object_acl_overrides_evaluated=False,
            effective_access_verified=False,
        )
        for bucket in buckets:
            graph.edge(nid, bucket["id"], "SUMMARIZES_BUCKET_CONTROLS", SOURCE)
        graph.coverage.append(
            dict(
                account=account,
                region="global",
                service="analysis",
                action="SummarizeCosAccountControls",
                status="unsupported",
                error="UnsupportedAccountLevelPublicAccessBlockEquivalence",
                count=len(buckets),
                request_ids=[],
            )
        )
