import ast

'''
    ast 모듈을 통해 노드 각각의 정보와 노드 간의 정보(엣지, 호출자-피호출자 관계)를 기록하는 스크립트
'''

# HTTP 메서드 이름 집합
RESTFUL_HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "options"}


def is_route_decorator(decorator_node: ast.AST) -> bool:
    if not isinstance(decorator_node, ast.Call):
        return False
    func_node = decorator_node.func
    return (
        isinstance(func_node, ast.Attribute)
        and isinstance(func_node.value, ast.Name)
        and func_node.attr == "route"
    )


def is_cli_decorator(decorator_node: ast.AST) -> bool:
    if not isinstance(decorator_node, ast.Call):
        return False
    func_node = decorator_node.func
    return (
        isinstance(func_node, ast.Attribute)
        and func_node.attr == "command"
        and isinstance(func_node.value, ast.Attribute)
        and func_node.value.attr == "cli"
        and isinstance(func_node.value.value, ast.Name)
    )


def is_socketio_decorator(decorator_node: ast.AST) -> bool:
    if not isinstance(decorator_node, ast.Call):
        return False
    func_node = decorator_node.func
    return (
        isinstance(func_node, ast.Attribute)
        and isinstance(func_node.value, ast.Name)
        and func_node.value.id == "socketio"
        and func_node.attr in ("on", "event")
    )


def uses_request(function_node: ast.AST) -> bool:
    for inner_node in ast.walk(function_node):
        if isinstance(inner_node, ast.Name) and inner_node.id == 'request':
            return True
    return False


def collect_functions(syntax_tree: ast.Module) -> dict[str, dict]:
    visitor = FuncVisitor()
    visitor.visit(syntax_tree)
    FuncVisitor().visit(syntax_tree)
    return visitor.function_info_map


class FuncVisitor(ast.NodeVisitor):
    def __init__(self):
        self.current_class_name = None
        self.function_info_map: dict[str, dict] = {}

    def visit_ClassDef(self, class_node: ast.ClassDef):
        prev_class = self.current_class_name
        self.current_class_name = class_node.name
        self.generic_visit(class_node)
        self.current_class_name = prev_class


    def visit_FunctionDef(self, function_node: ast.FunctionDef):
        if self.current_class_name:
            qualified_name = f"{self.current_class_name}.{function_node.name}"
        else:
            qualified_name = function_node.name

        self.function_info_map[qualified_name] = {
            'line': function_node.lineno,
            'is_route': any(is_route_decorator(dec) for dec in function_node.decorator_list),
            'is_cli': any(is_cli_decorator(dec) for dec in function_node.decorator_list),
            'is_socketio': any(is_socketio_decorator(dec) for dec in function_node.decorator_list),
            'uses_req': uses_request(function_node),
            'is_restful': False,
        }
        self.generic_visit(function_node)

class CallVisitor(ast.NodeVisitor):
    def __init__(
        self,
        force_detection: bool,
        module_prefix: str,
        source_code: str,
        relative_file_path: str,
        global_function_info_map: dict[str, dict],
        call_graph_map: dict[str, set[str]],
        target_call_specs: list[tuple[str | None, str]]
    ):
        self.current_function_name = None
        self.current_class_name = None
        self.force_detection = force_detection
        self.module_prefix = module_prefix
        self.source_code = source_code
        self.relative_file_path = relative_file_path
        self.global_function_info_map = global_function_info_map
        self.call_graph_map = call_graph_map
        self.target_call_specs = target_call_specs

    def visit_ClassDef(self, class_node: ast.ClassDef):
        prev_class = self.current_class_name
        self.current_class_name = class_node.name
        self.generic_visit(class_node)
        self.current_class_name = prev_class

    def visit_FunctionDef(self, function_node: ast.FunctionDef):
        if self.current_class_name:
            short_name = f"{self.current_class_name}.{function_node.name}"
        else:
            short_name = function_node.name

        if self.module_prefix:
            self.current_function_name = f"{self.module_prefix}.{short_name}"
        else:
            self.current_function_name = short_name

        self.generic_visit(function_node)
        self.current_function_name = None

    def visit_Call(self, call_node: ast.Call):
        # 데코레이터 기반 추가 탐지
        if isinstance(call_node.func, ast.Attribute):
            attribute_name = call_node.func.attr

            # socketio.on_event 핸들러
            if attribute_name == "on_event" and getattr(call_node.func.value, 'id', None) == "socketio":
                handler_node = (
                    call_node.args[1]
                    if len(call_node.args) >= 2
                    else next((kw.value for kw in call_node.keywords if kw.arg in ("handler", "callback")), None)
                )
                if isinstance(handler_node, (ast.Name, ast.Attribute)):
                    handler_name = handler_node.id if isinstance(handler_node, ast.Name) else handler_node.attr
                    for func_name in self.global_function_info_map:
                        if func_name.endswith(f".{handler_name}") or func_name == handler_name:
                            self.global_function_info_map[func_name]['is_socketio'] = True
                            break

            # flask.add_url_rule 기반 라우트 탐지
            elif attribute_name == "add_url_rule":
                view_func_node = next((kw.value for kw in call_node.keywords if kw.arg == "view_func"), None)
                if view_func_node is None:
                    if len(call_node.args) >= 3:
                        view_func_node = call_node.args[2]
                    elif len(call_node.args) == 2:
                        view_func_node = call_node.args[1]

                if view_func_node:
                    if isinstance(view_func_node, ast.Call) and getattr(view_func_node.func, 'attr', None) == "as_view":
                        class_node = view_func_node.func.value
                        class_name = getattr(class_node, 'id', getattr(class_node, 'attr', None))
                        for func_name in self.global_function_info_map:
                            if f".{class_name}." in func_name:
                                method_name = func_name.split('.')[-1]
                                if method_name in RESTFUL_HTTP_METHODS:
                                    self.global_function_info_map[func_name]['is_route'] = True
                    else:
                        func_name_candidate = (
                            view_func_node.id
                            if isinstance(view_func_node, ast.Name)
                            else view_func_node.attr
                            if isinstance(view_func_node, ast.Attribute)
                            else None
                        )
                        if func_name_candidate:
                            for fn in self.global_function_info_map:
                                if fn.endswith(f".{func_name_candidate}") or fn == func_name_candidate:
                                    self.global_function_info_map[fn]['is_route'] = True
                                    break

            # flask-restful add_resource 기반 RESTful 탐지
            elif attribute_name == "add_resource":
                resource_class_node = call_node.args[0] if call_node.args else None
                if isinstance(resource_class_node, (ast.Name, ast.Attribute)):
                    class_name = (
                        resource_class_node.id
                        if isinstance(resource_class_node, ast.Name)
                        else resource_class_node.attr
                    )
                    for func_name in self.global_function_info_map:
                        if f".{class_name}." in func_name:
                            method_name = func_name.split('.')[-1]
                            if method_name in RESTFUL_HTTP_METHODS:
                                self.global_function_info_map[func_name]['is_restful'] = True

            # socketio.on
            elif attribute_name == "on" and getattr(call_node.func.value, 'id', None) == "socketio":
                handler_node = (
                    call_node.args[1]
                    if len(call_node.args) >= 2
                    else next((kw.value for kw in call_node.keywords if kw.arg in ("handler", "callback")), None)
                )
                if isinstance(handler_node, (ast.Name, ast.Attribute)):
                    handler_name = handler_node.id if isinstance(handler_node, ast.Name) else handler_node.attr
                    for func_name in self.global_function_info_map:
                        if func_name.endswith(f".{handler_name}") or func_name == handler_name:
                            self.global_function_info_map[func_name]['is_socketio'] = True
                            break

        # caller-callee 관계 기록
        if self.current_function_name is not None:
            if isinstance(call_node.func, ast.Name):
                callee_name = call_node.func.id
            elif isinstance(call_node.func, ast.Attribute):
                callee_name = call_node.func.attr
                if callee_name in {"add_url_rule", "add_resource", "on_event", "on"}:
                    callee_name = None
            else:
                callee_name = None

            if callee_name:
                for func_name in self.global_function_info_map:
                    if func_name == self.current_function_name:
                        continue
                    if func_name.endswith(f".{callee_name}") or func_name == callee_name:
                        self.call_graph_map[self.current_function_name].add(func_name)
                        break

        # 타겟 API 호출 기록
        container_name = self.current_function_name or self.module_prefix or '<module>'
        is_target_call = self.force_detection or any(
            (module_name and isinstance(call_node.func, ast.Attribute)
             and getattr(call_node.func.value, 'id', None) == module_name
             and call_node.func.attr == func_name)
            or (module_name is None and isinstance(call_node.func, ast.Name)
                and call_node.func.id == func_name)
            for module_name, func_name in self.target_call_specs
        )
        if is_target_call:
            first_arg_source = (
                ast.get_source_segment(self.source_code, call_node.args[0])
                if call_node.args else ''
            )
            keyword_arg_sources = [
                f"{kw.arg}={ast.get_source_segment(self.source_code, kw.value)}"
                for kw in call_node.keywords
            ]
            self.call_graph_map.setdefault('target_calls', []).append(
                (container_name, call_node, first_arg_source, keyword_arg_sources, self.relative_file_path)
            )

        self.generic_visit(call_node)

