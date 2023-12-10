import datetime

from google.auth import _helpers
from google.auth import credentials
from google.auth import exceptions
from google.auth import iam
from google.auth import jwt
from google.auth import metrics
from google.auth.compute_engine import _metadata
from google.auth.transport import requests as google_auth_requests
from google.oauth2 import _client


class Credentials(credentials.Scoped, credentials.CredentialsWithQuotaProject):
    def __init__(
        self,
        service_account_email="default",
        quota_project_id=None,
        scopes=None,
        default_scopes=None,
    ):
        super(Credentials, self).__init__()
        self._service_account_email = service_account_email
        self._quota_project_id = quota_project_id
        self._scopes = scopes
        self._default_scopes = default_scopes
        self._universe_domain_cached = False
        self._universe_domain_request = google_auth_requests.Request()

    # 서비스 계정의 정보를 가져온다
    # 계정 정보를 가져와 해당 계정의 이메일을 업데이트하고, 필요한 경우에만 스코프(권한) 정보를 업데이트하는 함수
    def _retrieve_info(self, request):
        # GCE 메타데이터 서버에서 서비스 계정 정보를 가져온다
        info = _metadata.get_service_account_info(
            request, service_account=self._service_account_email
        )
        # 서비스 계정의 이메일 정보를 업데이트 한다
        self._service_account_email = info["email"]

        # 스코프 값을 업데이트한다
        if self._scopes is None:
            self._scopes = info["scopes"]

    # 인스턴스의 사용에 대한 메트릭 헤더 값을 반환한다
    def _metric_header_for_usage(self):
        return metrics.CRED_TYPE_SA_MDS

    # GCE 메타데이터 서버로부터 서비스 계정의 액세스 토큰을 다시 받아와 갱신하고, 경우에 따라 스코프도 업데이트한다
    def refresh(self, request):
        # 스코프가 없는 경우(None) 기본값을 사용한다
        scopes = self._scopes if self._scopes is not None else self._default_scopes
        # 서비스 계정 정보를 업데이트한다
        try:
            self._retrieve_info(request)
            self.token, self.expiry = _metadata.get_service_account_token(
                request, service_account=self._service_account_email, scopes=scopes
            )
        # exceptions.TransportError가 발생할 시 exceptions.RefreshError의 형태로 이를 다시 발생시킨다
        except exceptions.TransportError as caught_exc:
            new_exc = exceptions.RefreshError(caught_exc)
            raise new_exc from caught_exc

    # 서비스 계정 이메일을 속성으로 정의한다
    @property
    def service_account_email(self):
        return self._service_account_email

    # 스코프의 필요 여부를 속성으로 정의한다
    @property
    def requires_scopes(self):
        return not self._scopes

    @property
    def universe_domain(self):
        if self._universe_domain_cached:
            return self._universe_domain
        self._universe_domain = _metadata.get_universe_domain(
            self._universe_domain_request
        )
        self._universe_domain_cached = True
        return self._universe_domain

    @_helpers.copy_docstring(credentials.CredentialsWithQuotaProject)
    def with_quota_project(self, quota_project_id):
        return self.__class__(
            service_account_email=self._service_account_email,
            quota_project_id=quota_project_id,
            scopes=self._scopes,
        )

    # 위와 동일하나 초기화 하는 값의 차이가 존재한다
    @_helpers.copy_docstring(credentials.Scoped)
    def with_scopes(self, scopes, default_scopes=None):
        return self.__class__(
            scopes=scopes,
            default_scopes=default_scopes,
            service_account_email=self._service_account_email,
            quota_project_id=self._quota_project_id,
        )


# 토큰의 유효 시간(초단위로 표기, 즉 1시간)
_DEFAULT_TOKEN_LIFETIME_SECS = 3600
# Google OAuth 2.0 토큰을 얻기 위한 기본 URI
_DEFAULT_TOKEN_URI = "https://www.googleapis.com/oauth2/v4/token"


class IDTokenCredentials(
    credentials.CredentialsWithQuotaProject,
    credentials.Signing,
    credentials.CredentialsWithTokenUri,
):
    def __init__(
        self,
        request,
        target_audience,
        token_uri=None,
        additional_claims=None,
        service_account_email=None,
        signer=None,
        use_metadata_identity_endpoint=False,
        quota_project_id=None,
    ):
        super(IDTokenCredentials, self).__init__()

        self._quota_project_id = quota_project_id
        self._use_metadata_identity_endpoint = use_metadata_identity_endpoint
        self._target_audience = target_audience
        # GCE 메타데이터 ID 엔드포인트의 사용 여부
        if use_metadata_identity_endpoint:  # True인 경우 다른 필드들을 무시하고 GCE 메타데이터 ID 엔드포인트로부터 제공되는 정보로만 ID 토큰을 가져온다
            if token_uri or additional_claims or service_account_email or signer:
                raise exceptions.MalformedError(
                    "If use_metadata_identity_endpoint is set, token_uri, "
                    "additional_claims, service_account_email, signer arguments"
                    " must not be set"
                )
            # 엔드포인트로 부터 제공되는 정보에 의존하기에 이하 필드들을 초기화하지 않는다
            self._token_uri = None
            self._additional_claims = None
            self._signer = None

        # 서비스 계정 이메일 값이 존재하지 않는경우
        if service_account_email is None:
            # GCE 서비스 계정 정보를 가져와서 사용한다
            sa_info = _metadata.get_service_account_info(request)
            self._service_account_email = sa_info["email"]
        else:
            self._service_account_email = service_account_email

        if not use_metadata_identity_endpoint:
            if signer is None:
                signer = iam.Signer(
                    request=request,
                    credentials=Credentials(),
                    service_account_email=self._service_account_email,
                )
            self._signer = signer
            self._token_uri = token_uri or _DEFAULT_TOKEN_URI

            if additional_claims is not None:
                self._additional_claims = additional_claims
            else:
                self._additional_claims = {}

    # 주어진 target_audience(대상 청중)로 새로운 Credential 인스턴스를 생성하는 메소드
    def with_target_audience(self, target_audience):
        # 현재 Credential 인스턴스를 복사하여 target_audience만을 변경한 새로운 인스턴스를 생성해 반환한다
        # 조건문이 필요한 이유는 메타데이터 ID 엔드포인트의 사용 여부에 땨라 초기화 되는 변수들이 다르기 때문이다
        if self._use_metadata_identity_endpoint:
            return self.__class__(
                None,
                target_audience=target_audience,
                use_metadata_identity_endpoint=True,
                quota_project_id=self._quota_project_id,
            )
        else:
            return self.__class__(
                None,
                service_account_email=self._service_account_email,
                token_uri=self._token_uri,
                target_audience=target_audience,
                additional_claims=self._additional_claims.copy(),
                signer=self.signer,
                use_metadata_identity_endpoint=False,
                quota_project_id=self._quota_project_id,
            )

    # 주어진 quota_project_id(할당량 프로젝트 ID)로 새로운 Credentail 인스턴스를 생성하는 메소드
    @_helpers.copy_docstring(credentials.CredentialsWithQuotaProject)
    def with_quota_project(self, quota_project_id):
        # 현재 Credential 인스턴스를 복사하여 quota_project_id만을 변경한 새로운 인스턴스를 생성해 반환한다
        if self._use_metadata_identity_endpoint:
            return self.__class__(
                None,
                target_audience=self._target_audience,
                use_metadata_identity_endpoint=True,
                quota_project_id=quota_project_id,
            )
        else:
            return self.__class__(
                None,
                service_account_email=self._service_account_email,
                token_uri=self._token_uri,
                target_audience=self._target_audience,
                additional_claims=self._additional_claims.copy(),
                signer=self.signer,
                use_metadata_identity_endpoint=False,
                quota_project_id=quota_project_id,
            )

    # 주어진 token_uri(OAuth 2.0 토큰 URI)로 새로운 Credentail 인스턴스를 생성하는 메소드
    @_helpers.copy_docstring(credentials.CredentialsWithTokenUri)
    def with_token_uri(self, token_uri):
        # 현재 Credential 인스턴스를 복사하여 token_uri만을 변경한 새로운 인스턴스를 생성해 반환한다
        if self._use_metadata_identity_endpoint:  # 단 메타데이터 ID 엔드포인트 사용시 토큰 URI의 사용이 불가능하다
            # 예외를 발생시킨다
            raise exceptions.MalformedError(
                "If use_metadata_identity_endpoint is set, token_uri" " must not be set"
            )
        else:
            return self.__class__(
                None,
                service_account_email=self._service_account_email,
                token_uri=token_uri,
                target_audience=self._target_audience,
                additional_claims=self._additional_claims.copy(),
                signer=self.signer,
                use_metadata_identity_endpoint=False,
                quota_project_id=self.quota_project_id,
            )

    # OAuth 2.0 인증부여 assertion을 생성하는 메소드
    def _make_authorization_grant_assertion(self):
        now = _helpers.utcnow()  # 현재 시각(UTC)
        lifetime = datetime.timedelta(seconds=_DEFAULT_TOKEN_LIFETIME_SECS)  # 토큰의 유효 기간
        expiry = now + lifetime  # 토큰의 만료시간

        # 클레임
        payload = {
            # 발급 시간
            "iat": _helpers.datetime_to_secs(now),
            # 만료 시간
            "exp": _helpers.datetime_to_secs(expiry),
            # 서비스 계정 이메일(생성자)
            "iss": self.service_account_email,
            # 토큰이 발급될 OAuth 2.0 토큰 URI
            "aud": self._token_uri,
            "target_audience": self._target_audience,
        }
        # 추가적인 클레임이 있을 경우 payload에 업데이트한다
        payload.update(self._additional_claims)
        #  JWT(JSON Web Token)을 생성한다
        token = jwt.encode(self._signer, payload)

        return token

    # 메타데이터 ID 엔드포인트로부터 ID 토큰을 요청하는 메소드
    def _call_metadata_identity_endpoint(self, request):
        try:
            path = "instance/service-accounts/default/identity"
            params = {"audience": self._target_audience, "format": "full"}
            metrics_header = {
                metrics.API_CLIENT_HEADER: metrics.token_request_id_token_mds()
            }
            # get 메서드를 사용하여 특정 경로에서 ID 토큰(JWT)을 가져온다.
            id_token = _metadata.get(
                request, path, params=params, headers=metrics_header
            )
        except exceptions.TransportError as caught_exc:
            # RefreshErrord의 형태로 변환한다
            new_exc = exceptions.RefreshError(caught_exc)
            # 예외를 호출한 곳으로 전달힌다
            raise new_exc from caught_exc

        # JWT를 해독해 내용을 저장한다
        _, payload, _, _ = jwt._unverified_decode(id_token)
        # 토큰과 유효기간을 반환한다
        return id_token, datetime.datetime.utcfromtimestamp(payload["exp"])

    # ID 토큰을 새롭게 갱신하는 메소드
    def refresh(self, request):
        # 메타데이터 ID 엔드포인트에서 ID 토큰을 가져온다.
        if self._use_metadata_identity_endpoint:
            self.token, self.expiry = self._call_metadata_identity_endpoint(request)
        # assertion을 만들고 이를 사용해 ID 토큰을 얻는다
        else:
            assertion = self._make_authorization_grant_assertion()
            access_token, expiry, _ = _client.id_token_jwt_grant(
                request, self._token_uri, assertion
            )
            self.token = access_token
            self.expiry = expiry

    @property  # type: ignore
    @_helpers.copy_docstring(credentials.Signing)
    def signer(self):
        return self._signer

    # 주어진 메시지를 서명하는 메소드
    def sign_bytes(self, message):
        # 메타데이터 ID 엔드포인트를 사용하는 경우 Signer를 사용할 수 없다
        if self._use_metadata_identity_endpoint:
            raise exceptions.InvalidOperation(
                "Signer is not available if metadata identity endpoint is used"
            )
        # 암호화된 서명을 반환한다
        return self._signer.sign(message)

    @property
    def service_account_email(self):
        return self._service_account_email

    @property
    def signer_email(self):
        return self._service_account_email
