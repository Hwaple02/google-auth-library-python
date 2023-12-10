from __future__ import absolute_import

import io

from pyasn1.codec.der import decoder  # type: ignore
from pyasn1_modules import pem  # type: ignore
from pyasn1_modules.rfc2459 import Certificate  # type: ignore
from pyasn1_modules.rfc5208 import PrivateKeyInfo  # type: ignore
import rsa  # type: ignore

from google.auth import _helpers
from google.auth import exceptions
from google.auth.crypt import base

# 8비트 이진 표현의 각 비트에 해당하는 값을 나타내는 튜플
_POW2 = (128, 64, 32, 16, 8, 4, 2, 1)
# PEM 형식의 인증서를 확인하기 위한 마커
_CERTIFICATE_MARKER = b"-----BEGIN CERTIFICATE-----"
# PKCS#1 형식의 RSA 개인 키의 시작과 끝을 나타내는 튜플
_PKCS1_MARKER = ("-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----")
# PKCS  # 8 형식의 개인 키의 시작과 끝을 나타내는 튜플
_PKCS8_MARKER = ("-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----")
#  PKCS#8 개인 키 형식을 나타내는 변수
_PKCS8_SPEC = PrivateKeyInfo()


# 0과 1로 이루어진 비트 리스트를 바이트 형태로 변환해 반환하는 메소드
def _bit_list_to_bytes(bit_list):
    num_bits = len(bit_list)
    byte_vals = bytearray()
    # 입력된 비트 리스트를 8개씩 그룹화하여 처리한다
    for start in range(0, num_bits, 8):
        # 바이트 값을 계산해 리스트에 추가한다
        curr_bits = bit_list[start: start + 8]
        char_val = sum(val * digit for val, digit in zip(_POW2, curr_bits))
        byte_vals.append(char_val)
    # 바이트 값의 리스트를 바이트 객체로 변환하여 반환한다
    return bytes(byte_vals)


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
            return rsa.pkcs1.verify(message, signature, self._pubkey)
        except (ValueError, rsa.pkcs1.VerificationError):
            return False

    @classmethod
    def from_string(cls, public_key):
        # public_key를 바이트열로 변환한다
        public_key = _helpers.to_bytes(public_key)
        # 입력된 문자열이 X.509 공개키 인증서인지를 확인한다
        is_x509_cert = _CERTIFICATE_MARKER in public_key

        # 인증서인 경우
        if is_x509_cert:
            # DER 형식의 X.509 공개 키 인증서를 로드한다
            der = rsa.pem.load_pem(public_key, "CERTIFICATE")
            # DER 포맷의 X.509 인증서를 파싱한다
            asn1_cert, remaining = decoder.decode(der, asn1Spec=Certificate())
            if remaining != b"":
                raise exceptions.InvalidValue("Unused bytes", remaining)
            cert_info = asn1_cert["tbsCertificate"]["subjectPublicKeyInfo"]
            # 비트 리스트를 바이트로 변환한다
            key_bytes = _bit_list_to_bytes(cert_info["subjectPublicKey"])
            # 변환된 바이트를 사용하여 RSA 공개 키를 로드한다
            pubkey = rsa.PublicKey.load_pkcs1(key_bytes, "DER")
        # PEM 형식의 공개 키 문자열로부터 RSA 공개 키를 로드한다
        else:
            pubkey = rsa.PublicKey.load_pkcs1(public_key, "PEM")
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
        return rsa.pkcs1.sign(message, self._key, "SHA-256")

    @classmethod
    def from_string(cls, key, key_id=None):
        # 주어진 키를 바이트열로 변환한다
        key = _helpers.from_bytes(key)
        # PKCS#1 또는 PKCS#8 형식의 키인지 확인한다
        # 해당 포맷의 바이트를 가져온다
        marker_id, key_bytes = pem.readPemBlocksFromFile(
            io.StringIO(key), _PKCS1_MARKER, _PKCS8_MARKER
        )

        # PKCS#1 형식의 키를 읽고 DER 형식으로 로드한다
        if marker_id == 0:
            private_key = rsa.key.PrivateKey.load_pkcs1(key_bytes, format="DER")
        # PKCS#8 형식의 키를 디코딩하고 DER 형식으로 로드한다
        elif marker_id == 1:
            key_info, remaining = decoder.decode(key_bytes, asn1Spec=_PKCS8_SPEC)
            if remaining != b"":
                raise exceptions.InvalidValue("Unused bytes", remaining)
            private_key_info = key_info.getComponentByName("privateKey")
            private_key = rsa.key.PrivateKey.load_pkcs1(
                private_key_info.asOctets(), format="DER"
            )
        # 키의 형식을 찾지 못한경우
        else:
            raise exceptions.MalformedError("No key could be detected.")
        # 로드한 개인키로 RSASigner 클래스의 새로운 인스턴스를 생성해 반환한다
        return cls(private_key, key_id=key_id)
