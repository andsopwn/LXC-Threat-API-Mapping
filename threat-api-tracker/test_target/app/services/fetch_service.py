import urllib3
from app.utils.logger import logger

class FetchService:
    ALLOWED = {"example.com", "httpbin.org"}

    def fetch(self, url: str):
        logger.info(f"FetchService: fetching URL {url}")
        if not any(url.startswith(f"http://{h}") for h in self.ALLOWED):
            logger.warning("FetchService: URL blocked")
            raise PermissionError("blocked")
        http = urllib3.PoolManager()
        resp = http.request("GET", url)
        return {"status": resp.status, "body": resp.data[:50].decode(errors="ignore")}
