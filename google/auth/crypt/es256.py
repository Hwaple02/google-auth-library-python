from cryptography import utils  # type: ignore
import cryptography.exceptions
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
import cryptography.x509

from google.auth import _helpers
from google.auth.crypt import base


# PEM 형식의 인증서를 확인하기 위한 마커
_CERTIFICATE_MARKER = b"-----BEGIN CERTIFICATE-----"
# 암호화 작업을 수행하기 위한 백엔드를 지정한다
_BACKEND = backends.default_backend()
# 서명 및 암호화에 사용되는 패딩 방식을 지정한다
_PADDING = padding.PKCS1v15()


class ES256Verifier(base.Verifier):
    def __init__(self, public_key):
        self._pubkey = public_key

    # 주어진 메시지와 서명을 사용하여 서명의 유효성을 확인하는 메소드
    @_helpers.copy_docstring(base.Verifier)
    def verify(self, message, signature):
        # 메시지를 문자열에서 바이트열 형태로 변환한다
        sig_bytes = _helpers.to_bytes(signature)
        # 길이가 64인지 확인한다
        if len(sig_bytes) != 64:
            return False
        # (r||s) 형태의 원시 서명을 ASN.1 형식으로 변환한다ㄴ
        r = (
            # 바이트를 정수로 변환한다
            # 파이썬 버전이 3일때
            int.from_bytes(sig_bytes[:32], byteorder="big")
            if _helpers.is_python_3()
            # 파이썬 버전이 2일때
            else utils.int_from_bytes(sig_bytes[:32], byteorder="big")
        )
        s = (
            # 바이트를 정수로 변환한다
            int.from_bytes(sig_bytes[32:], byteorder="big")
            # 파이썬 버전이 3일때
            if _helpers.is_python_3()
            # 파이썬 버전이 2일때
            else utils.int_from_bytes(sig_bytes[32:], byteorder="big")
        )
        asn1_sig = encode_dss_signature(r, s)
        # 메시지를 문자열에서 바이트열 형태로 변환한다
        message = _helpers.to_bytes(message)
        # 서명의 유효 여부에 따라 True 혹은 False를 반환한다
        try:
            # ECDSA 및 SHA256 해시를 사용하여 검증한다
            self._pubkey.verify(asn1_sig, message, ec.ECDSA(hashes.SHA256()))
            return True
        except (ValueError, cryptography.exceptions.InvalidSignature):
            return False

    #  문자열로부터 공개 키 혹은 인증서를 파싱하여 Verifier 클래스의 인스턴스를 생성하는 메소드
    @classmethod
    def from_string(cls, public_key):
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
        # Verifier 클래스의 새로운 인스턴스를 생성해 반환한다
        return cls(pubkey)


class ES256Signer(base.Signer, base.FromServiceAccountMixin):
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
        # 주어진 메시지에 대한 ECDSA(SHA256) 서명을 생성한다
        asn1_signature = self._key.sign(message, ec.ECDSA(hashes.SHA256()))
        # ASN.1 형식의 서명을 (r, s) 형태로 분리한다
        (r, s) = decode_dss_signature(asn1_signature)
        # 파이썬 버전 3과 2에 따라 방법을 달리하여 (r||s) 형태의 raw 서명을 생성해 반환한다
        return (
            (r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big"))
            if _helpers.is_python_3()  # 파이썬 버전 3
            else (utils.int_to_bytes(r, 32) + utils.int_to_bytes(s, 32))  # 파이썬 버전 2
        )

    #  PEM 형식의 개인 키를 넘겨받아 RSASigner 객체를 생성하는 메소드
    @classmethod
    def from_string(cls, key, key_id=None):
        # 주어진 키를 바이트열로 변환한다
        key = _helpers.to_bytes(key)
        # PEM 형식의 개인 키 문자열을 개인 키 객체로 파싱한다
        private_key = serialization.load_pem_private_key(
            key, password=None, backend=_BACKEND
        )
        # RSASigner 클래스의 새로운 인스턴스를 생성해 반환한다
        return cls(private_key, key_id=key_id)

    # 객체를 직렬화 하는 메소드
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

    # 객체를 역직렬화하는 메소드
    def __setstate__(self, state):
        # 직렬화된 키를 역직렬화해 저장한다
        state["_key"] = serialization.load_pem_private_key(state["_key"], None)
        # 역직렬화된 상태를 __dict__에 업데이트하여 객체를 복원한다
        self.__dict__.update(state)
