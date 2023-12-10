import datetime
import http.client as http_client
import json
import logging
import os
from urllib.parse import urljoin

from google.auth import _helpers
from google.auth import environment_vars
from google.auth import exceptions
from google.auth import metrics

# 로거 설정: 현재 모듈의 로그를 가져온다
_LOGGER = logging.getLogger(__name__)

# 환경변수에서 값을 가져와 GCE(Google Compute Engine) 메타데이터 서버의 호스트를 설정한다
_GCE_METADATA_HOST = os.getenv(environment_vars.GCE_METADATA_HOST, None)
if not _GCE_METADATA_HOST:  # 가져온 값이 존재하지 않는다면 기존에 사용되던 환경변수를 사용한다
    _GCE_METADATA_HOST = os.getenv(
        environment_vars.GCE_METADATA_ROOT, "metadata.google.internal"
    )
# 최종적으로 구성된 메타데이터 서버의 루트 URL을 나타낸다
_METADATA_ROOT = "http://{}/computeMetadata/v1/".format(_GCE_METADATA_HOST)

# GCE 메타데이터 서버의 IP주소를 가져온다 (단, 환경변수가 설정되어 있지 않다면 기본값으로 "169.254.169.254"를 사용한다)
_METADATA_IP_ROOT = "http://{}".format(
    os.getenv(environment_vars.GCE_METADATA_IP, "169.254.169.254")
)
# HTTP 요청 헤더의 이름
_METADATA_FLAVOR_HEADER = "metadata-flavor"
# HTTP 요청 헤더의 값
_METADATA_FLAVOR_VALUE = "Google"
# HTTP 요청 시 사용할 헤더들을 나타내는 딕셔너리
_METADATA_HEADERS = {_METADATA_FLAVOR_HEADER: _METADATA_FLAVOR_VALUE}

# GCE 메타데이터 서버에 대한 타임아웃을 설정한다
try:
    _METADATA_DEFAULT_TIMEOUT = int(os.getenv("GCE_METADATA_TIMEOUT", 3))  # 환경변수가 존재하지 않을 시 기본값 3
except ValueError:
    _METADATA_DEFAULT_TIMEOUT = 3  # 정수로 값 할당이 불가능해 오류 발생시 기본값 3

_GOOGLE = "Google"
_GCE_PRODUCT_NAME_FILE = "/sys/class/dmi/id/product_name"


# GCE에서 실행 중인지 감지하는 함수
def is_on_gce(request):
    # 메타데이터 서버에 핑을 보내서 서버의 응답여부를 확인한다
    if ping(request):
        return True

    # 현재 운영체재가 Windows인지 확인한다
    if os.name == "nt":
        return False

    # 현재 운영체재가 Linux환경인지 확인한다
    return detect_gce_residency_linux()


# 현재 운영체제가 Linux 환경인지 확인하는 함수
def detect_gce_residency_linux():
    try:
        # /sys/class/dmi/id/product_name 파일을 내용을 읽어온다
        with open(_GCE_PRODUCT_NAME_FILE, "r") as file_obj:
            content = file_obj.read().strip()

    except Exception:
        return False
    # 읽어온 내용이 Google로 시작하는지 여부를 통해 GCE환경이 Linux환경인지 감지한다
    return content.startswith(_GOOGLE)


# GCE 메타데이터 서버에 핑을 보내서 서버의 응답여부 확인하는 함수
def ping(request, timeout=_METADATA_DEFAULT_TIMEOUT, retry_count=3):
    retries = 0
    headers = _METADATA_HEADERS.copy()
    headers[metrics.API_CLIENT_HEADER] = metrics.mds_ping()

    # 주어진 횟수만큼 서버에 핑을 보내고 응답한다면 True반환
    while retries < retry_count:
        try:
            response = request(
                url=_METADATA_IP_ROOT, method="GET", headers=headers, timeout=timeout
            )

            metadata_flavor = response.headers.get(_METADATA_FLAVOR_HEADER)
            return (
                    response.status == http_client.OK
                    and metadata_flavor == _METADATA_FLAVOR_VALUE
            )

        except exceptions.TransportError as e:
            # GCE 메타데이터 서버 접근 불가 경고
            _LOGGER.warning(
                "Compute Engine Metadata server unavailable on "
                "attempt %s of %s. Reason: %s",
                retries + 1,
                retry_count,
                e,
            )
            retries += 1

    return False


# 메타데이터 서버에서 리소스를 가져오는 함수
# HTTP GET 요청을 사용하여 메타데이터 서버에 특정 리소스를 요청하고 응답을 처리하여 결과를 반환한다
def get(
        request,
        path,
        root=_METADATA_ROOT,
        params=None,
        recursive=False,
        retry_count=5,
        headers=None,
):
    # 루트와 경로 결합하여 전체 url을 생성한다
    base_url = urljoin(root, path)
    query_params = {} if params is None else params

    headers_to_use = _METADATA_HEADERS.copy()
    if headers:
        headers_to_use.update(headers)

    if recursive:
        query_params["recursive"] = "true"

    url = _helpers.update_query(base_url, query_params)

    retries = 0
    # 연결 시도 횟수에 도달할 때까지 서버에 GET 요청을 보낸다
    while retries < retry_count:
        try:
            # 요청 보내기
            response = request(url=url, method="GET", headers=headers_to_use)
            break

        except exceptions.TransportError as e:
            # 에러 발생시 로그 남기고 재시도
            _LOGGER.warning(
                "Compute Engine Metadata server unavailable on "
                "attempt %s of %s. Reason: %s",
                retries + 1,
                retry_count,
                e,
            )
            retries += 1
    else:
        # 모든 요청이 실패 했다면 TransportError를 발생시킨다
        raise exceptions.TransportError(
            "Failed to retrieve {} from the Google Compute Engine "
            "metadata service. Compute Engine Metadata server unavailable".format(url)
        )

    # 응답이 성공했을 시 상태코드가 200인지 확인한다
    if response.status == http_client.OK:
        # 응답 데이터를 문자열로 디코딩한다
        content = _helpers.from_bytes(response.data)
        # 응답의 타입이 JSON일 경우 JSON으로 디코딩 하여 반환한다
        if (
                _helpers.parse_content_type(response.headers["content-type"])
                == "application/json"
        ):
            try:
                return json.loads(content)
            except ValueError as caught_exc:
                new_exc = exceptions.TransportError(
                    "Received invalid JSON from the Google Compute Engine "
                    "metadata service: {:.20}".format(content)
                )
                raise new_exc from caught_exc
        # JSON이 아니라면 그대로 반환한다
        else:
            return content
    else:
        # 모든 요청이 실패 했다면 TransportError에러를 발생시킨다.
        raise exceptions.TransportError(
            "Failed to retrieve {} from the Google Compute Engine "
            "metadata service. Status: {} Response:\n{}".format(
                url, response.status, response.data
            ),
            response,
        )


# get 함수를 호출하여 메타데이터 서버에서 project/product-id 리소스를 가져온다
def get_project_id(request):
    return get(request, "project/project-id")


# GCE 메타데이터 서버에서 서비스 계정에 관한 정보를 가져오는 함수
def get_service_account_info(request, service_account="default"):
    path = "instance/service-accounts/{0}/".format(service_account)
    return get(request, path, params={"recursive": "true"})


# GCE 메타데이터 서버에서 서비스 계정에 대한 OAuth 2.0 액세스 토큰을 가져오는 함수
def get_service_account_token(request, service_account="default", scopes=None):
    if scopes:
        # 스코프가 지정되어 있으면 스트링이 아닌 경우 이를 합쳐서 쿼리 파라미터로 사용한다
        if not isinstance(scopes, str):
            scopes = ",".join(scopes)
        params = {"scopes": scopes}
    else:
        params = None

    # 액세스 토큰을 요청하기 위한 헤더를 설정한다
    metrics_header = {
        metrics.API_CLIENT_HEADER: metrics.token_request_access_token_mds()
    }

    # 특정 서비스 계정의 액세스 토큰을 가져온다
    path = "instance/service-accounts/{0}/token".format(service_account)
    token_json = get(request, path, params=params, headers=metrics_header)

    # 액세스 토큰의 만료 시간을 계산한다
    token_expiry = _helpers.utcnow() + datetime.timedelta(
        seconds=token_json["expires_in"]
    )

    # 액세스 토큰과 만료 시간을 반환한다
    return token_json["access_token"], token_expiry

