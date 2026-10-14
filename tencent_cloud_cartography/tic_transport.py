"""Read-only legacy TIC metadata contract via the official common SDK client."""

import re

from .transport import CollectionError

ACTIONS = {"DescribeStacks", "DescribeStackVersions", "DescribeStackEvents"}


def call(profile, action, region, params, timeout):
    if action not in ACTIONS or not set(params) <= {"Offset", "Limit", "Filters"}:
        raise CollectionError("BlockedTicAction")
    if (
        not isinstance(region, str)
        or not re.fullmatch(r"[a-z]+-[a-z0-9-]+", region)
        or type(params.get("Offset")) is not int
        or params["Offset"] < 0
        or type(params.get("Limit")) is not int
        or not 1 <= params["Limit"] <= 100
    ):
        raise CollectionError("InvalidTicScope")
    if "Filters" in params:
        filters = params["Filters"]
        if (
            action == "DescribeStacks"
            or not isinstance(filters, list)
            or len(filters) != 1
            or not isinstance(filters[0], dict)
            or set(filters[0]) != {"Name", "Values"}
            or filters[0]["Name"] != "StackId"
            or not isinstance(filters[0]["Values"], list)
            or len(filters[0]["Values"]) != 1
            or not re.fullmatch(r"stk-[a-z0-9]+", str(filters[0]["Values"][0]))
        ):
            raise CollectionError("InvalidTicScope")
    from tencentcloud.common.common_client import CommonClient
    from tencentcloud.common.credential import Credential
    from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
    from tencentcloud.common.profile.client_profile import ClientProfile
    from tencentcloud.common.profile.http_profile import HttpProfile

    from .cos_transport import credentials

    selected = credentials(profile)
    http = HttpProfile()
    http.endpoint = "tic.tencentcloudapi.com"
    http.reqTimeout = timeout
    config = ClientProfile()
    config.httpProfile = http
    client = CommonClient(
        "tic",
        "2020-11-17",
        Credential(selected["SecretId"], selected["SecretKey"], selected.get("Token")),
        region,
        config,
    )
    try:
        result = client.call_json(action, params)
    except TencentCloudSDKException as exc:
        code = exc.get_code()
        raise CollectionError(
            code
            if isinstance(code, str) and re.fullmatch(r"[A-Za-z0-9.]+", code)
            else "TicApiError"
        ) from None
    if not isinstance(result, dict) or not isinstance(result.get("Response"), dict):
        raise CollectionError("InvalidTicResponse")
    return result["Response"]
