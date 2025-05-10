import ast
import os
import argparse
from collections import defaultdict
from graphviz import Digraph

def parse_target_calls(targets: list[str]) -> list[tuple[str | None, str]]:
    pairs = []
    for t in targets:
        parts = t.split('.', 1)
        if len(parts) == 1:
            pairs.append((None, parts[0]))
        else:
            pairs.append((parts[0], parts[1]))
    return pairs

def is_route_decorator(dec: ast.AST) -> bool:
    if not isinstance(dec, ast.Call):
        return False
    func = dec.func
    return (isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.attr == "route")

def is_cli_decorator(dec: ast.AST) -> bool:
    if not isinstance(dec, ast.Call):
        return False
    func = dec.func
    return (isinstance(func, ast.Attribute)
            and func.attr == "command"
            and isinstance(func.value, ast.Attribute)
            and func.value.attr == "cli"
            and isinstance(func.value.value, ast.Name))

def is_socketio_decorator(dec: ast.AST) -> bool:
    if not isinstance(dec, ast.Call):
        return False
    func = dec.func
    return (isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == "socketio"
            and func.attr in ("on", "event"))

def uses_request(node: ast.AST) -> bool:
    return any(isinstance(n, ast.Name) and n.id == 'request' for n in ast.walk(node))

def collect_functions(tree: ast.Module) -> dict[str, dict]:
    func_info = {}
    class FuncVisitor(ast.NodeVisitor):
        def __init__(self):
            self.cls = None
        def visit_ClassDef(self, node):
            prev_cls = self.cls
            self.cls = node.name
            self.generic_visit(node)
            self.cls = prev_cls
        def visit_FunctionDef(self, node):
            name = f"{self.cls}.{node.name}" if self.cls else node.name
            func_info[name] = {
                'line': node.lineno,
                'is_route': any(is_route_decorator(d) for d in node.decorator_list),
                'is_cli': any(is_cli_decorator(d) for d in node.decorator_list),
                'is_socketio': any(is_socketio_decorator(d) for d in node.decorator_list),
                'uses_req': uses_request(node),
                'is_restful': False,
            }
            self.generic_visit(node)

    FuncVisitor().visit(tree)
    return func_info

def invert_graph(call_graph: dict[str, set[str]]) -> dict[str, set[str]]:
    inv = defaultdict(set)
    for caller, callees in call_graph.items():
        for callee in callees:
            inv[callee].add(caller)
    return inv

def collect_related(target_calls, callers_map):
    related = set()
    for fn, *_ in target_calls:
        related.add(fn)
        stack = [fn]
        while stack:
            cur = stack.pop()
            for parent in callers_map.get(cur, []):
                if parent not in related:
                    related.add(parent)
                    stack.append(parent)
    return related

def sanitize_id(name: str) -> str:
    return name.replace('.', '_').replace(' ', '_').replace('/', '_')

def visualize_call_flow(file_paths, base_dir, output_path, targets):
    global_func_info = {}
    call_graph = defaultdict(set)
    target_calls = []

    # HTTP 메서드 이름 집합 (Flask-RESTful)
    restful_http_methods = {"get", "post", "put", "delete", "patch", "head", "options"}

    # 함수 정의 수집
    for fp in file_paths:
        try:
            code = open(fp, encoding='utf-8').read()
            tree = ast.parse(code)
        except Exception:
            continue
        rel_path = os.path.relpath(fp, base_dir)
        prefix = rel_path.replace(os.sep, '.')[:-3] if rel_path.endswith('.py') else rel_path.replace(os.sep, '.')
        if prefix == '':
            prefix = os.path.splitext(os.path.basename(fp))[0]
        funcs = collect_functions(tree)
        for name, info in funcs.items():
            full_name = f"{prefix}.{name}" if prefix else name
            info['file'] = rel_path
            global_func_info[full_name] = info

    # 호출 그래프 구축 및 진입점 등록 탐지
    for fp in file_paths:
        try:
            code = open(fp, encoding='utf-8').read()
            tree = ast.parse(code)
        except Exception:
            continue
        rel_path = os.path.relpath(fp, base_dir)
        prefix = rel_path.replace(os.sep, '.')[:-3] if rel_path.endswith('.py') else rel_path.replace(os.sep, '.')
        if prefix == '':
            prefix = os.path.splitext(os.path.basename(fp))[0]

        class CallVisitor(ast.NodeVisitor):
            def __init__(self):
                self.cur_func = None
                self.cls = None
            def visit_ClassDef(self, node):
                prev_cls = self.cls
                self.cls = node.name
                self.generic_visit(node)
                self.cls = prev_cls
            def visit_FunctionDef(self, node):
                prev = self.cur_func
                func_name = f"{self.cls}.{node.name}" if self.cls else node.name
                self.cur_func = f"{prefix}.{func_name}" if prefix else func_name
                self.generic_visit(node)
                self.cur_func = prev

            def visit_Call(self, node):
                # 진입점 등록 호출 탐지
                if isinstance(node.func, ast.Attribute):
                    attr = node.func.attr
                    # SocketIO on_event
                    if attr == "on_event" and getattr(node.func.value, 'id', None) == "socketio":
                        handler = (node.args[1] if len(node.args)>=2 else
                                   next((kw.value for kw in node.keywords if kw.arg in ("handler", "callback")), None))
                        if isinstance(handler, (ast.Name, ast.Attribute)):
                            hname = handler.id if isinstance(handler, ast.Name) else handler.attr
                            for fn in global_func_info:
                                if fn == hname or fn.endswith(f".{hname}"):
                                    global_func_info[fn]['is_socketio'] = True
                                    break
                    # add_url_rule
                    elif attr == "add_url_rule":
                        view_node = next((kw.value for kw in node.keywords if kw.arg=="view_func"), None)
                        if view_node is None:
                            # view_func 추출
                            if len(node.args)>=3:
                                view_node = node.args[2]
                            elif len(node.args)==2:
                                view_node = node.args[1]
                        if view_node:
                            # 클래스 기반 뷰
                            if isinstance(view_node, ast.Call) and getattr(view_node.func, 'attr', None)=="as_view":
                                cls_node = view_node.func.value
                                cls_name = getattr(cls_node, 'id', getattr(cls_node, 'attr', None))
                                if cls_name:
                                    for fn in global_func_info:
                                        if f".{cls_name}." in fn:
                                            method = fn.split('.')[-1]
                                            if method in restful_http_methods:
                                                global_func_info[fn]['is_route'] = True
                            else:
                                name = (view_node.id if isinstance(view_node, ast.Name)
                                        else view_node.attr if isinstance(view_node, ast.Attribute)
                                        else None)
                                if name:
                                    for fn in global_func_info:
                                        if fn == name or fn.endswith(f".{name}"):
                                            global_func_info[fn]['is_route'] = True
                                            break
                    elif attr == "add_resource":
                        cls_node = node.args[0] if node.args else None
                        if isinstance(cls_node, (ast.Name, ast.Attribute)):
                            cls_name = cls_node.id if isinstance(cls_node, ast.Name) else cls_node.attr
                            for fn in global_func_info:
                                if f".{cls_name}." in fn:
                                    method = fn.split('.')[-1]
                                    if method in restful_http_methods:
                                        global_func_info[fn]['is_restful'] = True
                    # SocketIO on 
                    elif attr == "on" and getattr(node.func.value, 'id', None)=="socketio":
                        handler = (node.args[1] if len(node.args)>=2 else
                                   next((kw.value for kw in node.keywords if kw.arg in ("handler","callback")), None))
                        if isinstance(handler, (ast.Name, ast.Attribute)):
                            hname = handler.id if isinstance(handler, ast.Name) else handler.attr
                            for fn in global_func_info:
                                if fn == hname or fn.endswith(f".{hname}"):
                                    global_func_info[fn]['is_socketio'] = True
                                    break

                # 호출 그래프용 일반 호출 간선 추가
                if self.cur_func is None:
                    self.generic_visit(node)
                    return

                if isinstance(node.func, ast.Name):
                    callee = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    callee = node.func.attr
                    if callee in {"add_url_rule","add_resource","on_event","on"}:
                        callee = None
                else:
                    callee = None

                if callee:
                    for fn in global_func_info:
                        if fn == self.cur_func:
                            continue
                        if fn == callee or fn.endswith(f".{callee}"):
                            call_graph[self.cur_func].add(fn)
                            break

                ok = False
                for mod, func in targets:
                    if mod:
                        if (isinstance(node.func, ast.Attribute)
                                and isinstance(node.func.value, ast.Name)
                                and node.func.value.id==mod and node.func.attr==func):
                            ok = True
                            break
                    else:
                        if isinstance(node.func, ast.Name) and node.func.id==func:
                            ok = True
                            break
                if ok:
                    cont = self.cur_func or prefix or '<module>'
                    a0 = ast.get_source_segment(code, node.args[0]) if node.args else ''
                    kws = [f"{kw.arg}={ast.get_source_segment(code,kw.value)}" for kw in node.keywords]
                    target_calls.append((cont, node, a0, kws, rel_path))

                self.generic_visit(node)

        CallVisitor().visit(tree)

    # 외부 함수 집합 구성
    external_funcs = {
        fn for fn, info in global_func_info.items()
        if info.get('is_route') or info.get('is_cli')
        or info.get('is_socketio') or info.get('is_restful')
    }

    stack = list(external_funcs)
    
    while stack:
        cur = stack.pop()
        for callee in call_graph.get(cur, []):
            if callee not in external_funcs:
                external_funcs.add(callee)
                stack.append(callee)

    # 시각화
    rel_map = invert_graph(call_graph)
    related = collect_related(target_calls, rel_map)
    labels = [f"{(m + '.' if m else '')}{f}" for m, f in targets]
    dot = Digraph(comment="Call flow for " + ", ".join(labels))
    dot.attr(rankdir='LR', bgcolor='white')
    dot.attr('node', style='filled')
    dot.attr('edge', fontcolor='black')

    # 시작 함수 노드 정의
    for fn in sorted(related):
        info = global_func_info.get(fn, {})
        lbl = f"{fn}\n(file: {info.get('file','?')}, line: {info.get('line','?')})"
        tags = []
        if info.get('is_route'):      tags.append('route')
        if info.get('is_restful'):    tags.append('restful')
        if info.get('is_cli'):        tags.append('cli')
        if info.get('is_socketio'):   tags.append('socketio')
        if info.get('uses_req'):      tags.append('uses_request')
        if tags:
            lbl += "\n[" + ",".join(tags) + "]"
        fill = 'lightgoldenrod' if (info.get('is_route') or info.get('is_cli')
                                    or info.get('is_socketio') or info.get('is_restful')) else 'white'
        dot.node(sanitize_id(fn), label=lbl, fillcolor=fill)

    # 타겟 함수 노드 정의
    for cont, node, a0, kws, rel_path in target_calls:
        ln = node.lineno
        api = (f"{node.func.value.id}.{node.func.attr}"
               if isinstance(node.func, ast.Attribute) else node.func.id)
        lbl = f"{api}\n(file: {rel_path}, line: {ln})"
        if a0: lbl += f"\narg0: {a0}"
        if kws: lbl += "\n" + ",".join(kws)
        ext = cont in external_funcs
        lbl += f"\n[{'external' if ext else 'internal'}]"
        cid = sanitize_id(f"call_{cont}_{ln}")
        dot.node(cid, label=lbl, shape='oval',
                 fillcolor=('lightcoral' if ext else 'lightblue'))
        dot.edge(sanitize_id(cont), cid, label=f"calls (line {ln})")

    # 노드간 간선 연결
    for caller, callees in call_graph.items():
        if caller in related:
            for callee in callees:
                if callee in related:
                    dot.edge(sanitize_id(caller), sanitize_id(callee), label='calls')

    dot.format = 'png'
    dot.render(output_path, cleanup=True)
    print(f"[+] Graph saved as {output_path}.png")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('path', help='Path to the Python file/folder to analyze')
    parser.add_argument('-o', '--output', default='callflow', help='Output filename prefix')
    parser.add_argument('-t', '--target', action='append', default=[], help='Target function(s) to highlight (e.g., yaml.load)')
    args = parser.parse_args()

    target_list = args.target or ['yaml.load']
    targets = parse_target_calls(target_list)

    input_path = args.path

    if os.path.isdir(input_path):
        base = input_path.rstrip(os.sep)
        files = []
        for root, _, filenames in os.walk(input_path):
            for f in filenames:
                if f.endswith('.py'):
                    files.append(os.path.join(root, f))
    else:
        base = os.path.dirname(input_path) or '.'
        files = [input_path]

    visualize_call_flow(files, base, args.output, targets)
