import io
import os
from multipart import MultipartParser
from werkzeug.utils import secure_filename
from app.utils.logger import logger

class FileService:
    def upload(self, raw_data: bytes, content_type: str):
        logger.info("FileService: handling file upload")
        parser = MultipartParser(io.BytesIO(raw_data), content_type)
        for part in parser.parts():
            filename = secure_filename(part.filename or "upload.bin")
            with open(filename, "wb") as f:
                f.write(part.raw)
            size = os.path.getsize(filename)
            logger.info(f"Saved file {filename} ({size} bytes)")
            return {"file": filename, "size": size}
        raise ValueError("no part")
