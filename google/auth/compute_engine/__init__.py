# 필요한 모듈 임포트
from google.auth.compute_engine._metadata import detect_gce_residency_linux
from google.auth.compute_engine.credentials import Credentials
from google.auth.compute_engine.credentials import IDTokenCredentials

# 외부에 노출되는 클래스 선별
__all__ = ["Credentials", "IDTokenCredentials", "detect_gce_residency_linux"]
