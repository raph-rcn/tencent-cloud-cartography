"""Fixed official international SDK operation missing from the local TCCLI catalog."""

import json
import re

from .transport import CollectionError


def call(profile, action, region, params, timeout):
    if action != "DescribeReservedInstances" or set(params) != {"Offset", "Limit"}:
        raise CollectionError("BlockedInternationalAction")
    if (
        not isinstance(region, str)
        or not re.fullmatch(r"[a-z]+-[a-z0-9-]+", region)
        or type(params["Offset"]) is not int
        or params["Offset"] < 0
        or type(params["Limit"]) is not int
        or not 1 <= params["Limit"] <= 100
    ):
        raise CollectionError("InvalidInternationalScope")
    from tencentcloud.common.credential import Credential
    from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
    from tencentcloud.common.profile.client_profile import ClientProfile
    from tencentcloud.common.profile.http_profile import HttpProfile
    from tencentcloud.cvm.v20170312 import cvm_client, models

    from .cos_transport import credentials

    selected = credentials(profile)
    http = HttpProfile()
    http.endpoint = "cvm.intl.tencentcloudapi.com"
    http.reqTimeout = timeout
    config = ClientProfile()
    config.httpProfile = http
    client = cvm_client.CvmClient(
        Credential(selected["SecretId"], selected["SecretKey"], selected.get("Token")),
        region,
        config,
    )
    request = models.DescribeReservedInstancesRequest()
    request.from_json_string(json.dumps(params))
    try:
        result = json.loads(client.DescribeReservedInstances(request).to_json_string())
    except TencentCloudSDKException as exc:
        code = exc.get_code()
        raise CollectionError(
            code
            if isinstance(code, str) and re.fullmatch(r"[A-Za-z0-9.]+", code)
            else "InternationalApiError"
        ) from None
    except (ValueError, TypeError):
        raise CollectionError("InvalidInternationalResponse") from None
    if not isinstance(result, dict):
        raise CollectionError("InvalidInternationalResponse")
    return result
