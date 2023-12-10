try:
    from google.auth.crypt import _cryptography_rsa
    # _cryptography_rsa 모듈이 존재한다면 아래의 값들을 가져온다
    RSASigner = _cryptography_rsa.RSASigner
    RSAVerifier = _cryptography_rsa.RSAVerifier
# 만약 _cryptography_rsa 모듈이 존재하지 않는경우
except ImportError:
    # 순수 파이썬으로 작성된 _python_rsa 모듈에서 값들을 가져온다
    from google.auth.crypt import _python_rsa

    RSASigner = _python_rsa.RSASigner
    RSAVerifier = _python_rsa.RSAVerifier
