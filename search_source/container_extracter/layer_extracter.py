import tarfile
import json
import os
import shutil
import tempfile

CANDIDATE_APP_PATHS = ["/app", "/usr/src/app", "/src", "/code", "/workspace"]  # 소스 예상 경로

def extract_app_layer(image_tar_path: str, output_dir: str, app_path: str = None, auto_detect=False, include_filter: str = None):
    with tempfile.TemporaryDirectory() as temp_dir:
        print(f"[+] Extracting image tar: {image_tar_path}")
        with tarfile.open(image_tar_path, "r") as tar:
            tar.extractall(path=temp_dir)

        manifest_path = os.path.join(temp_dir, "manifest.json")
        with open(manifest_path, "r") as f:
            manifest = json.load(f)

        layers = manifest[0]["Layers"]
        merged_fs = os.path.join(temp_dir, "merged_fs")
        os.makedirs(merged_fs, exist_ok=True)

        for layer_tar in layers:
            layer_tar_path = os.path.join(temp_dir, layer_tar)
            with tarfile.open(layer_tar_path, "r") as layer_tarfile:
                layer_tarfile.extractall(path=merged_fs)
            print(f"[+] Applied layer: {layer_tar}")

        app_src = None
        if auto_detect:
            found = False
            for candidate in CANDIDATE_APP_PATHS:
                test_path = os.path.join(merged_fs, candidate.strip("/"))
                if os.path.exists(test_path):
                    dest_path = os.path.join(output_dir, candidate.strip("/"))
                    shutil.copytree(test_path, dest_path)
                    print(f"[+] Auto-copied: {candidate} → {dest_path}")
                    found = True
            if not found:
                raise FileNotFoundError("[!] No app paths found in auto-detect mode.")
            return

        else:
            app_src = os.path.join(merged_fs, app_path.strip("/"))
            if not os.path.exists(app_src):
                raise FileNotFoundError(f"[!] Specified app path not found: {app_path}")

        if os.path.exists(output_dir):
            shutil.rmtree(output_dir)
        os.makedirs(output_dir)

        for root, _, files in os.walk(app_src):
            rel_root = os.path.relpath(root, app_src)
            dest_root = os.path.join(output_dir, rel_root)
            os.makedirs(dest_root, exist_ok=True)

            for file in files:
                if include_filter and include_filter not in file:
                    continue
                src_file = os.path.join(root, file)
                dst_file = os.path.join(dest_root, file)
                shutil.copy2(src_file, dst_file)

        print(f"[+] Application files copied to: {output_dir}")
