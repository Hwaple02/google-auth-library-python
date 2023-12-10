from google.auth.crypt import base
from google.auth.crypt import rsa

try:
    from google.auth.crypt import es256
except ImportError:
    es256 = None

# es256 존재 여부에 따라 _all__의 내용을 달리한다
if es256 is not None:
    __all__ = [
        "ES256Signer",
        "ES256Verifier",
        "RSASigner",
        "RSAVerifier",
        "Signer",
        "Verifier",
    ]
else:
    __all__ = ["RSASigner", "RSAVerifier", "Signer", "Verifier"]

# 별칭 설정
Signer = base.Signer
Verifier = base.Verifier
RSASigner = rsa.RSASigner
RSAVerifier = rsa.RSAVerifier

if es256 is not None:
    ES256Signer = es256.ES256Signer
    ES256Verifier = es256.ES256Verifier


# 메시지와 서명을 받아서 여러 인증서로부터 어떤 인증서가 해당 서명을 인증하는데 사용될 수 있는지 확인하는 메소드
def verify_signature(message, signature, certs, verifier_cls=rsa.RSAVerifier):
    if isinstance(certs, (str, bytes)):
        certs = [certs]

    for cert in certs:
        verifier = verifier_cls.from_string(cert)
        # 유효한 서명이 발견되면 True를 반환하고 종료한다
        if verifier.verify(message, signature):
            return True
    return False
