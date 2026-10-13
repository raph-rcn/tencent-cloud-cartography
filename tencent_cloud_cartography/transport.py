"""TCCLI metadata transport, with a dedicated official SDK adapter for COS XML."""

import json
import re
import subprocess
import time

from .catalog import ALLOWED_ACTIONS, API_VERSIONS, SES_ENDPOINTS


class CollectionError(RuntimeError):
    def __init__(self, code, message="Collection failed"):
        self.code = code
        super().__init__(message)


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
    def __init__(self, profile="default", executable="tccli", timeout=90):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", profile) or profile in {".", ".."}:
            raise ValueError("Invalid TCCLI profile name")
        self.profile, self.executable, self.timeout = profile, executable, timeout

    def _run(self, service, action, region, params):
        if (service, action) not in ALLOWED_ACTIONS:
            raise CollectionError(
                "BlockedAction", f"{service}.{action} is outside the metadata allowlist"
            )
        args = [
            self.executable,
            service,
            action,
            "--profile",
            self.profile,
            "--output",
            "json",
            "--timeout",
            str(self.timeout),
        ]
        if service == "ses":
            if region not in SES_ENDPOINTS:
                raise CollectionError("UnsupportedSesRegion")
            args.extend(["--endpoint", SES_ENDPOINTS[region]])
        if service in API_VERSIONS:
            args.extend(["--version", API_VERSIONS[service]])
        if region and region != "global":
            args.extend(["--region", region])
        for key, value in params.items():
            if not re.fullmatch("[A-Za-z][A-Za-z0-9_]*", key):
                raise ValueError("Invalid API parameter")
            args.extend(
                [
                    "--" + key,
                    json.dumps(value) if isinstance(value, (list, dict, bool)) else str(value),
                ]
            )
        try:
            result = subprocess.run(
                args, capture_output=True, text=True, timeout=self.timeout + 30, check=False
            )
        except FileNotFoundError as exc:
            raise CollectionError("TccliNotFound", "Install TCCLI or provide --tccli") from exc
        except subprocess.TimeoutExpired as exc:
            raise CollectionError("Timeout") from exc
        if result.returncode:
            raise CollectionError(failure_code(result.stdout + result.stderr))
        return result.stdout

    def buckets(self):
        # The COS plugin gives environment credentials precedence. Reject ambiguous
        # mixed sources so it cannot silently inventory a different account.
        import os
        from pathlib import Path

        credential = Path.home() / ".tccli" / (self.profile + ".credential")
        if (
            any(
                os.environ.get(k)
                for k in ("TENCENTCLOUD_SECRET_ID", "TENCENTCLOUD_SECRET_KEY", "TENCENTCLOUD_TOKEN")
            )
            and credential.exists()
        ):
            raise CollectionError("CredentialSourceConflict")
        return parse_buckets(self._run("cos", "list_buckets", None, {}))

    def call(self, service, action, region=None, **params):
        if service == "cos":
            from .cos_transport import call

            return call(self.profile, action, region, params, self.timeout)
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
            if spec.paging in {"page", "offset-page", "zero-offset-page", "number-page"}
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
