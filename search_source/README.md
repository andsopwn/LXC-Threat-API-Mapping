# container_extractor
Extract application layer from a Docker image .tar file without using Docker.

## Features
- Extracts all layers in the image tarball (docker save output)

- Automatically detects common app paths (e.g., /app, /usr/src/app, etc.)

- Optionally filters files by extension or keyword (e.g., .py)

## Usage
```bash
python main.py <image_tar> <output_dir> [--app-path <path>] [--auto-detect] [--include <filter>]
```
- Example 1: Auto-detect application path
```bash
python main.py test_container.tar ./output --auto-detect
```
- Example 2: Specify app path manually
```bash
python main.py test_container.tar ./output --app-path /usr/src/app
```
- Example 3: Only extract .py files
```bash
python main.py test_container.tar ./output --auto-detect --include .py
```
## Expected Structure
This tool expects a .tar file created by:

```bash
docker save your_image_name -o test_container.tar
```