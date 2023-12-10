import abc
import io
import json

from google.auth import exceptions

# 서비스 계정의 개인 키
_JSON_FILE_PRIVATE_KEY = "private_key"
# 서비스 계정의 개인 키를 식별하는데 사용되는 키
_JSON_FILE_PRIVATE_KEY_ID = "private_key_id"


# 여러 종류의 검증 기능의 구현을 위한 추상 클래스
class Verifier(metaclass=abc.ABCMeta):
    # 기능이 구현되어 있지 않아 상속하는 클래스는 추상 메소드를 오버라이드해 미구현된 기능을 구현해야 한다
    # 주어진 메시지와 서명을 사용하여 서명의 유효성을 확인하는 메소드
    @abc.abstractmethod
    def verify(self, message, signature):
        raise NotImplementedError("Verify must be implemented")


# 여러 종류의 서명 알고리즘 및 키 관리 체계를 지원하는 다양한 서명 클래스 구현을 위한 추상 클래스
class Signer(metaclass=abc.ABCMeta):
    # 기능이 구현되어 있지 않아 상속하는 클래스는 추상 메소드들을 오버라이드해 미구현된 기능을 구현해야 한다
    # key_id 속성을 제공하는 메소드
    @abc.abstractproperty
    def key_id(self):
        raise NotImplementedError("Key id must be implemented")

    # 서명 기능을 수행하는 메소드
    @abc.abstractmethod
    def sign(self, message):
        raise NotImplementedError("Sign must be implemented")


class FromServiceAccountMixin(metaclass=abc.ABCMeta):
    # 기능이 구현되어 있지 않아 상속하는 클래스는 반드시 추상 메소드들을 오버라이드해 미구현된 기능을 구현해야 한다
    # 문자열 형태의 개인 키를 받아 Signer 인스턴스를 생성하는 메소드
    @abc.abstractmethod
    def from_string(cls, key, key_id=None):
        raise NotImplementedError("from_string must be implemented")
    # 서비스 계정 정보를 가져와 Signer 인스턴스를 생성하는 메소드
    @classmethod
    def from_service_account_info(cls, info):
        # info 딕셔너리 안에는 _JSON_FILE_PRIVATE_KEY 키가 존재해야만 한다
        if _JSON_FILE_PRIVATE_KEY not in info:
            raise exceptions.MalformedError(
                "The private_key field was not found in the service account " "info."
            )
        # 서비스 계정 정보가 있는 JSON 파일의 정보를 바탕으로 Signerㄴ 인스턴스를 생성해 반환한다
        return cls.from_string(
            info[_JSON_FILE_PRIVATE_KEY], info.get(_JSON_FILE_PRIVATE_KEY_ID)
        )

    # 서비스 계정 정보가 있는 JSON 파일을 읽은 후 데이터를 딕셔너리로 로드하는 메소드
    @classmethod
    def from_service_account_file(cls, filename):
        with io.open(filename, "r", encoding="utf-8") as json_file:
            data = json.load(json_file)

        return cls.from_service_account_info(data)
