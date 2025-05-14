from app.services.yaml_service import YamlService
from app.utils.logger import logger

class ParseService:
    def __init__(self, yaml_service: YamlService):
        self.yaml_service = yaml_service

    def parse(self, text: str):
        logger.info("ParseService: parsing YAML input")
        return self.yaml_service.load(text)
