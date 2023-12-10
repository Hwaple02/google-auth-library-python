import cryptography.exceptions
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
import cryptography.x509

from google.auth import _helpers
from google.auth.crypt import base

# PEM 형식의 인증서를 확인하기 위한 마커
_CERTIFICATE_MARKER = b"-----BEGIN CERTIFICATE-----"
# 암호화 작업을 수행하기 위한 백엔드를 지정한다
_BACKEND = backends.default_backend()
# 서명 및 암호화에 사용되는 패딩 방식을 지정한다
_PADDING = padding.PKCS1v15()
# 사용하는 해시 알고리즘
_SHA256 = hashes.SHA256()


# 공개 키를 이용하여 서명을 검증하는 기능을 수행하는 클래스
class RSAVerifier(base.Verifier):
    def __init__(self, public_key):
        self._pubkey = public_key

    # 주어진 메시지와 서명을 사용하여 서명의 유효성을 확인하는 메소드
    @_helpers.copy_docstring(base.Verifier)
    def verify(self, message, signature):
        # 메시지를 문자열에서 바이트열 형태로 변환한다
        message = _helpers.to_bytes(message)
        # 서명의 유효 여부에 따라 True 혹은 False를 반환한다
        try:
            self._pubkey.verify(signature, message, _PADDING, _SHA256)
            return True
        except (ValueError, cryptography.exceptions.InvalidSignature):
            return False

    #  문자열로부터 공개 키 혹은 인증서를 파싱하여 RSAVerifier 클래스의 인스턴스를 생성하는 메소드
    @classmethod
    def from_string(cls, public_key):
        # public_key를 바이트열로 변환한다
        public_key_data = _helpers.to_bytes(public_key)

        # 입력된 문자열이 인증서인지를 확인한다
        if _CERTIFICATE_MARKER in public_key_data:
            # X.509 형식의 인증서 객체로 변환한다
            cert = cryptography.x509.load_pem_x509_certificate(
                public_key_data, _BACKEND
            )
            # 인증서에서 공개 키 값을 추출한다
            pubkey = cert.public_key()
        # 인증서가 아니라면 문자열로부터 공개 키를 직접 파싱한다
        else:
            pubkey = serialization.load_pem_public_key(public_key_data, _BACKEND)
        # RSAVerifier 클래스의 새로운 인스턴스를 생성해 반환한다
        return cls(pubkey)


class RSASigner(base.Signer, base.FromServiceAccountMixin):
    def __init__(self, private_key, key_id=None):
        self._key = private_key
        self._key_id = key_id

    @property
    @_helpers.copy_docstring(base.Signer)
    def key_id(self):
        return self._key_id

    # 주어진 메시지에 서명을 생성하는 메소드
    @_helpers.copy_docstring(base.Signer)
    def sign(self, message):
        # 주어진 메시지를 바이트열로 변환한다
        message = _helpers.to_bytes(message)
        # RSA 개인 키 객체를 사용하여 주어진 메시지에 대한 서명을 생성해 반환한다
        return self._key.sign(message, _PADDING, _SHA256)

    # RSA 개인 키를 넘겨받아 RSASigner 클래스의 새로운 인스턴스를 생성하는 메소드
    @classmethod
    def from_string(cls, key, key_id=None):
        # 주어진 키를 바이트열로 변환한다
        key = _helpers.to_bytes(key)
        # PEM 형식의 개인 키 문자열을 RSA 개인 키 객체로 파싱한다
        private_key = serialization.load_pem_private_key(
            key, password=None, backend=_BACKEND
        )
        # RSASigner 클래스의 새로운 인스턴스를 생성해 반환한다
        return cls(private_key, key_id=key_id)

    # 객체를 직렬화하는 메소드
    def __getstate__(self):
        # __dict__는 객체의 속성을 담고 있는 딕셔너리로, 객체의 상태를 표현하는데 사용된다
        state = self.__dict__.copy()
        # _key 속성에 있는 RSA 개인 키를 직렬화하여 저장한다
        state["_key"] = self._key.private_bytes(
            encoding=serialization.Encoding.PEM,  # PEM 형식으로 변환한다
            format=serialization.PrivateFormat.PKCS8,  # PKCS8 형식으로 인코딩 한다
            encryption_algorithm=serialization.NoEncryption(),  # 암호화를 사용하지 않는다
        )
        # 직렬화된 상태를 담고있는 딕셔너리를 반환한다
        return state

    # 객체를 역질렬화하는 메소드
    def __setstate__(self, state):
        # 직렬화된 키를 RSA 개인 키 객체로 변환한다
        state["_key"] = serialization.load_pem_private_key(state["_key"], None)
        # 역직렬화된 상태를 __dict__에 업데이트하여 객체를 복원한다
        self.__dict__.update(state)
