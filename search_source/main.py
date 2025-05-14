import argparse

from container_extracter import layer_extracter

CANDIDATE_APP_PATHS = ["/app", "/usr/src/app", "/src", "/code", "/workspace"]  # 소스 예상 경로

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract app layer from Docker image tar (no Docker needed).")
    parser.add_argument("image_tar", help="Path to Docker image tar file")
    parser.add_argument("output_dir", help="Directory to copy extracted app layer")
    parser.add_argument("--app-path", help="Path inside container to extract (e.g., /app)")
    parser.add_argument("--auto-detect", action="store_true", help="Automatically detect application path")
    parser.add_argument("--include", help="Only include files that contain this string (e.g., .py)")

    args = parser.parse_args()

    try:
        layer_extracter.extract_app_layer(
            image_tar_path=args.image_tar,
            output_dir=args.output_dir,
            app_path=args.app_path,
            auto_detect=args.auto_detect,
            include_filter=args.include
        )
    except Exception as e:
        print(f"[ERROR] {e}")