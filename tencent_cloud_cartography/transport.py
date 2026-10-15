"""TCCLI metadata transport, with a dedicated official SDK adapter for COS XML."""

import json
import re
import time

from .catalog import ALLOWED_ACTIONS, SES_ENDPOINTS
from .errors import CollectionError as CollectionError


def failure_code(text):
    match = re.search(
        r"(?i)(UnauthorizedOperation(?:\.[A-Za-z]+)*|OperationDenied(?:\.[A-Za-z]+)*|AuthFailure(?:\.[A-Za-z]+)*|RequestLimitExceeded(?:\.[A-Za-z]+)*|ResourceNotFound(?:\.[A-Za-z]+)*|InvalidAction|UnsupportedOperation(?:\.[A-Za-z]+)*)",
        text,
    )
    if match:
        return match.group(0)
    if "secretId is invalid" in text or "secretKey is invalid" in text:
        return "MissingCredentials"
    return "CliError"


class TccliTransport:
    def __init__(
        self, profile="default", executable="tccli", timeout=90, tccli_python=None, session=None
    ):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", profile) or profile in {".", ".."}:
            raise ValueError("Invalid TCCLI profile name")
        from .authentication import VerifiedSession
        from .tccli_runtime import TccliRuntime

        self.profile, self.executable, self.timeout = profile, executable, timeout
        self.runtime = TccliRuntime(executable, tccli_python, timeout)
        self.session = session or VerifiedSession(profile, self.runtime)

    def authentication_report(self):
        return self.session.report()

    def _run(self, service, action, region, params):
        validate_operation(service, action, region, params)
        return json.dumps(
            self.session.execute(
                lambda material: self.runtime.invoke(
                    "metadata",
                    service=service,
                    action=action,
                    region=region,
                    params=params,
                    material=material.wire(),
                )
            )
        )

    def buckets(self):
        rows, names, markers, marker, owner = [], set(), set(), "", None
        for _ in range(10000):
            response = self.call("cos", "list_buckets", Marker=marker, MaxKeys=2000)
            current_owner = (
                response.get("Owner", {}).get("ID")
                if isinstance(response.get("Owner", {}), dict)
                else None
            )
            if owner is not None and current_owner != owner:
                raise CollectionError("InventoryChanged")
            owner = current_owner
            if "Buckets" not in response:
                raise CollectionError("InvalidCosBucketList")
            buckets = response["Buckets"]
            if buckets in (None, ""):
                buckets = {}
            if not isinstance(buckets, dict):
                raise CollectionError("InvalidCosBucketList")
            page = buckets.get("Bucket", [])
            if isinstance(page, dict):
                page = [page]
            if not isinstance(page, list):
                raise CollectionError("InvalidCosBucketList")
            for row in page:
                if (
                    not isinstance(row, dict)
                    or not isinstance(row.get("Name"), str)
                    or not re.fullmatch(r"[a-z0-9][a-z0-9-]*-\d+", row["Name"])
                    or not isinstance(row.get("Location"), str)
                    or not re.fullmatch(r"[a-z]+-[a-z0-9-]+", row["Location"])
                ):
                    raise CollectionError("InvalidCosBucketList")
                if row["Name"] in names:
                    raise CollectionError("PaginationStalled")
                names.add(row["Name"])
                rows.append(dict(name=row["Name"], region=row["Location"]))
            next_marker = response.get("NextMarker", "")
            if next_marker is None:
                next_marker = ""
            if not isinstance(next_marker, str):
                raise CollectionError("InvalidCosBucketList")
            if not next_marker:
                if response.get("IsTruncated") in (True, "true"):
                    raise CollectionError("IncompletePagination")
                return rows
            if not page or next_marker in markers or next_marker == marker:
                raise CollectionError("PaginationStalled")
            markers.add(next_marker)
            marker = next_marker
        raise CollectionError("PageLimit")

    def call(self, service, action, region=None, **params):
        validate_operation(service, action, region, params)
        adapter = None
        if service == "cos":
            from . import cos_transport as adapter
        elif service == "tic":
            from . import tic_transport as adapter
        elif service == "cvm" and action == "DescribeReservedInstances":
            from . import international as adapter
        if adapter:
            adapter.validate_scope(action, region, params)
            return self.session.execute(
                lambda material: adapter.call(
                    self.profile, action, region, params, self.timeout, material=material
                )
            )
        for attempt in range(4):
            try:
                raw = self._run(service, action, region, params)
                result = json.loads(raw)
                if not isinstance(result, dict):
                    raise CollectionError("InvalidResponse")
                result = result.get("Response", result)
                if not isinstance(result, dict):
                    raise CollectionError("InvalidResponse")
                if "Error" in result:
                    raise CollectionError(result["Error"].get("Code", "ApiError"))
                if not isinstance(result, dict):
                    raise CollectionError("InvalidResponse")
                return result
            except json.JSONDecodeError as exc:
                raise CollectionError("InvalidResponse", "TCCLI did not return JSON") from exc
            except CollectionError as exc:
                if not exc.code.lower().startswith("requestlimitexceeded") or attempt == 3:
                    raise
                time.sleep(2**attempt)
        raise CollectionError("RetryExhausted")


def validate_operation(service, action, region, params):
    if (service, action) not in ALLOWED_ACTIONS:
        raise CollectionError(
            "BlockedAction", f"{service}.{action} is outside the metadata allowlist"
        )
    if not isinstance(params, dict) or any(
        not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", k) for k in params
    ):
        raise CollectionError("BlockedParameterScope")
    if (
        region
        and region != "global"
        and (not isinstance(region, str) or not re.fullmatch(r"[a-z]+-[a-z0-9-]+", region))
    ):
        raise CollectionError("InvalidRegion")
    if service == "ses" and region not in SES_ENDPOINTS:
        raise CollectionError("UnsupportedSesRegion")
    if (service, action) == ("postgres", "DescribeDBInstanceParameters"):
        from .database_depth import PG_PARAMETERS

        if (
            set(params) != {"DBInstanceId", "ParamName"}
            or params.get("ParamName") not in PG_PARAMETERS
        ):
            raise CollectionError("BlockedParameterScope")


def path_value(obj, path, default=None):
    for part in path.split("."):
        if not isinstance(obj, dict) or part not in obj:
            return default
        obj = obj[part]
    return obj


def pages(transport, spec, region, params=None, max_pages=10000):
    """Fail on missing arrays, stalled pages, changing totals, and premature EOF."""
    base, cursor, seen, count, expected = dict(params or {}), 0, set(), 0, None
    for _ in range(max_pages):
        query = dict(base)
        if spec.paging in {"offset", "zero-offset-page"}:
            query.update(Offset=cursor, Limit=spec.page_size)
        elif spec.paging == "page-size":
            query.update(Page=cursor + 1, PageSize=spec.page_size)
        elif spec.paging == "page":
            query.update(Page=cursor + 1, Rp=spec.page_size)
        elif spec.paging == "offset-page":
            query.update(Offset=cursor + 1, Limit=spec.page_size)
        elif spec.paging == "number-page":
            query.update(PageNumber=cursor + 1, PageSize=10)
        response = transport.call(spec.service, spec.action, region=region, **query)
        items = path_value(response, spec.result)
        if not isinstance(items, list):
            raise CollectionError("InvalidResponse", "Expected a resource array")
        total = path_value(response, spec.total) if spec.total else None
        if spec.require_total and (type(total) is not int or total < 0):
            raise CollectionError("InvalidTotal")
        if total is not None:
            try:
                total = int(total)
            except (ValueError, TypeError) as exc:
                raise CollectionError("InvalidTotal") from exc
            if expected is not None and total != expected:
                raise CollectionError(
                    "InventoryChanged", "Resource count changed during pagination; retry"
                )
            expected = total
        signature = json.dumps(items, sort_keys=True)
        if items and signature in seen:
            raise CollectionError("PaginationStalled")
        seen.add(signature)
        count += len(items)
        yield items, response.get("RequestId")
        if spec.paging == "none" or (total is not None and count >= total):
            if total is not None and count != total:
                raise CollectionError("CountMismatch")
            return
        if not items:
            if total is not None and count < total:
                raise CollectionError("IncompletePagination")
            return
        if total is None and len(items) < (10 if spec.paging == "number-page" else spec.page_size):
            return
        cursor = (
            cursor + 1
            if spec.paging
            in {"page", "page-size", "offset-page", "zero-offset-page", "number-page"}
            else cursor + len(items)
        )
    raise CollectionError("PageLimit")


def parse_buckets(raw):
    """COS's TCCLI plugin emits a table, even with --output json. Fail closed."""
    if "Error:" in raw or "错误" in raw:
        raise CollectionError(failure_code(raw))
    if raw.strip() == "当前账号下没有存储桶":
        return []
    rows = []
    for line in raw.splitlines():
        match = re.fullmatch(r"\s*([a-z0-9][a-z0-9-]+-\d+)\s+([a-z]+-[a-z0-9-]+)\s+(\S+)\s*", line)
        if match:
            rows.append(dict(name=match[1], region=match[2]))
    total = re.search(r"共\s*(\d+)\s*个存储桶", raw)
    if not total or int(total[1]) != len(rows) or "BucketName" not in raw:
        raise CollectionError("UnsupportedCosOutput")
    return rows
