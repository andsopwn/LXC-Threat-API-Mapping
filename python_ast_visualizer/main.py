import os
import argparse
import logging

from utils import ast_to_png

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('path', help='Path to Python file or folder')
    parser.add_argument('-o','--output', default='callflow', help='Output prefix')
    parser.add_argument('-t','--target', action='append', default=[], help='Highlight target functions (e.g. yaml.load)')
    args=parser.parse_args()

    target_list=args.target
    force = len(target_list)==0
    targets=ast_to_png.parse_target_calls(target_list)
    
    input_path=args.path
    if os.path.isdir(input_path):
        base=input_path.rstrip(os.sep)
        files=[]
        for r,_,fns in os.walk(input_path): # 폴더 이름은 필요없음
            for fn in fns:
                if fn.endswith('.py'):
                    files.append(os.path.join(r,fn))
        logging.info(f"Collected {len(files)} Python files for analysis")
    else:
        base=os.path.dirname(input_path) or '.'
        files=[input_path]
        logging.info(f"Single file mode: {input_path}")

    external_apis, internal_only_apis, unused_apis = ast_to_png.visualize_call_flow(files, base, args.output, targets, force)
    
    print("Externally exposed APIs:")
    for api in external_apis:
        print(f"  {api}")
    print("\nInternally only APIs:")
    for api in internal_only_apis:
        print(f"  {api}")
    print("\nUnused APIs:")
    for api in unused_apis:
        print(f"  {api}")

if __name__ == '__main__':
    main()