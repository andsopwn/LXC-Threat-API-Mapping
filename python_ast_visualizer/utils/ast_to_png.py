import ast
from collections import defaultdict
import logging
import os
from graphviz import Digraph

from . import ast_utils  # 노드 정보 기입 모듈

'''
    로드된 노드들의 정보를 통해 시각화하는 스크립트
'''

def get_full_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        base_name = get_full_name(node.value)
        return f"{base_name}.{node.attr}" if base_name else node.attr
    return ''


def invert_graph(call_graph: dict[str, set[str]]) -> dict[str, set[str]]:
    inverse_map: dict[str, set[str]] = defaultdict(set)
    for caller_function, callee_functions in call_graph.items():
        for callee_function in callee_functions:
            inverse_map[callee_function].add(caller_function)
    return inverse_map


def collect_related_functions(target_call_entries: list, callers_map: dict[str, set[str]]) -> set[str]:
    related_functions = set()
    for function_name, *_ in target_call_entries:
        related_functions.add(function_name)
        stack = [function_name]
        while stack:
            current = stack.pop()
            for parent in callers_map.get(current, []):
                if parent not in related_functions:
                    related_functions.add(parent)
                    stack.append(parent)
    return related_functions


def parse_target_calls(target_call_strings: list[str]) -> list[tuple[str | None, str]]:
    parsed_targets: list[tuple[str|None,str]] = []
    for target_string in target_call_strings:
        parts = target_string.split('.', 1)
        if len(parts) == 1:
            parsed_targets.append((None, parts[0]))
        else:
            parsed_targets.append((parts[0], parts[1]))
    return parsed_targets


def sanitize_node_identifier(name: str) -> str:
    return name.replace('.', '_').replace(' ', '_').replace('/', '_')


def visualize_call_flow(
    file_paths: list[str],
    base_directory: str,
    output_path: str,
    target_call_list: list,
    force_detection: bool
):
    logging.info(f"Starting analysis on {len(file_paths)} files in {base_directory}")
    global_function_info: dict[str, dict] = {}
    call_graph: dict[str, set[str]] = defaultdict(set)
    collected_target_calls: list = []

    # 플래그 - 태그 매핑
    DETECTION_FLAG_TO_TAG = {
        'is_route':    'route',
        'is_restful':  'restful',
        'is_cli':      'cli',
        'is_socketio': 'socketio',
        'uses_req':    'uses_request',
    }
    ROUTE_DETECTION_FLAGS = (
        'is_route',
        'is_cli',
        'is_socketio',
        'is_restful',
    )

    # 함수 정의 정보 수집
    for file_path in file_paths:
        try:
            source_code = open(file_path, encoding='utf-8').read()
            syntax_tree = ast.parse(source_code)
        except Exception:
            continue

        relative_path = os.path.relpath(file_path, base_directory)
        module_prefix = (
            relative_path.replace(os.sep, '.')[:-3]
            if file_path.endswith('.py')
            else relative_path.replace(os.sep, '.')
        )
        if not module_prefix:
            module_prefix = os.path.splitext(os.path.basename(file_path))[0]

        functions_in_file = ast_utils.collect_functions(syntax_tree)
        for function_name, function_info in functions_in_file.items():
            full_function_name = f"{module_prefix}.{function_name}" if module_prefix else function_name
            function_info['file'] = relative_path
            global_function_info[full_function_name] = function_info

    # force 모드에서 yaml 타겟 기본 처리
    if force_detection and target_call_list == [(None, 'yaml')]:
        target_call_list.clear()
        for function_name, function_info in global_function_info.items():
            if any(function_info.get(flag, False) for flag in ROUTE_DETECTION_FLAGS):
                target_call_list.append((None, function_name.split('.')[-1]))

    # 호출 그래프 생성 및 타겟 호출 수집
    for file_path in file_paths:
        try:
            source_code = open(file_path, encoding='utf-8').read()
            syntax_tree = ast.parse(source_code)
        except Exception:
            continue

        relative_path = os.path.relpath(file_path, base_directory)
        module_prefix = (
            relative_path.replace(os.sep, '.')[:-3]
            if file_path.endswith('.py')
            else relative_path.replace(os.sep, '.')
        )
        if not module_prefix:
            module_prefix = os.path.splitext(os.path.basename(file_path))[0]

        visitor = ast_utils.CallVisitor(
        force_detection,         # 강제 탐지 모드 여부 (True면 targets 검증 없이 모든 호출을 기록)
        module_prefix,           # 현재 파일의 모듈 경로 접두사 ex) 패키지명.모듈명
        source_code,  # 현재 파일의 전체 소스 코드
        relative_path,  # 프로젝트 기준 상대 경로
        global_function_info,  # collect_functions()로 수집된 모든 함수 정보 맵
        call_graph,  # caller-callee 관계를 기록하는 그래프 구조체
        target_call_list  # (module, func) 튜플 형태의 타겟 API 호출 명세 리스트
        )
        visitor.visit(syntax_tree)  # AST를 순회하며 호출 정보 및 target_calls를 수집

        if 'target_calls' in call_graph:
            collected_target_calls.extend(call_graph.pop('target_calls'))

    # 외부 함수 집합 확장
    external_functions = {
        fn for fn, info in global_function_info.items()
        if any(info.get(flag, False) for flag in ROUTE_DETECTION_FLAGS)
    }
    extension_stack = list(external_functions)
    while extension_stack:
        current_function = extension_stack.pop()
        for callee in call_graph.get(current_function, []):
            if callee not in external_functions:
                external_functions.add(callee)
                extension_stack.append(callee)

    # 그래프 역방향 맵핑 및 관련 함수 수집
    reversed_call_map = invert_graph(call_graph)
    related_functions = collect_related_functions(collected_target_calls, reversed_call_map)

    # 시각화
    target_labels = [
        f"{(module + '.') if module else ''}{func}"
        for module, func in target_call_list
    ]
    graph = Digraph(comment="Call flow for " + ", ".join(target_labels))
    graph.attr(rankdir='LR', bgcolor='white')
    graph.attr('node', style='filled')
    graph.attr('edge', fontcolor='black')

    # 함수 정의 노드 생성 (정의의 범위는 제공한 소스로 한정)
    for function_name in sorted(related_functions):
        info = global_function_info.get(function_name, {})
        label = f"{function_name}\n(file: {info.get('file','?')}, line: {info.get('line','?')})"
        tags = [
            tag for flag, tag in DETECTION_FLAG_TO_TAG.items()
            if info.get(flag, False)
        ]
        if tags:
            label += "\n[" + ",".join(tags) + "]"
        fill_color = (
            'lightgoldenrod'
            if any(info.get(flag, False) for flag in ROUTE_DETECTION_FLAGS)
            else 'white'
        )
        graph.node(sanitize_node_identifier(function_name), label=label, fillcolor=fill_color)

    # 함수 호출 노드 생성, 위의 정의 노드가 호출되는 노드를 생성 후 간선 연결 
    for container_function, call_node, first_arg, keyword_args, relative_path in collected_target_calls:
        line_number = call_node.lineno
        api_full_name = get_full_name(call_node.func)
        call_label = f"{api_full_name}\n(file: {relative_path}, line: {line_number})"
        if first_arg:
            call_label += f"\narg0: {first_arg}"
        if keyword_args:
            call_label += "\n" + ",".join(keyword_args)
        is_external_call = container_function in external_functions
        call_label += f"\n[{'external' if is_external_call else 'internal'}]"
        call_id = sanitize_node_identifier(f"call_{container_function}_{line_number}")
        graph.node(call_id, label=call_label, shape='oval',
                   fillcolor=('lightcoral' if is_external_call else 'lightblue'))
        graph.edge(sanitize_node_identifier(container_function), call_id,
                   label=f"calls (line {line_number})")

    # caller, callee 관계에 따른 간선 연결
    for caller_function, callee_functions in call_graph.items():
        if caller_function in related_functions:
            for callee_function in callee_functions:
                if callee_function in related_functions:
                    graph.edge(
                        sanitize_node_identifier(caller_function),
                        sanitize_node_identifier(callee_function),
                        label='calls'
                    )

    graph.format = 'png'
    graph.render(output_path, cleanup=True)
    logging.info(f"Graph saved to {output_path}.png")
