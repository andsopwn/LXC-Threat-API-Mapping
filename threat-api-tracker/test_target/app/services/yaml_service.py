import yaml
from app.utils.logger import logger

class YamlService:
    def __init__(self, loader=yaml.Loader):
        self.loader = loader

    def load(self, text: str):
        logger.info("YamlService: loading text via yaml.load")
        return yaml.load(text, Loader=self.loader)
