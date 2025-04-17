from __future__ import annotations
from binaryninja import BinaryView, PluginCommand, show_plain_text_report, log_info
from typing import List, Set

MAX_DEPTH = None
INCLUDE_LIBRARY_FUNCTIONS = False

MAIN_CANDIDATES = [
    "main",
    "main.main",
]

MAIN_SUFFIXES = [
    ".main",
    "::main",
]

def locate_main(bv: BinaryView):
    for name in MAIN_CANDIDATES:
        for func in bv.functions:
            if func.name == name:
                return func
    for func in bv.functions:
        if any(func.name.endswith(suffix) for suffix in MAIN_SUFFIXES):
            return func
    return None

def generate_call_tree(func, output: List[str], indent: int, visited: Set[int], depth: int, call_stack: List[int]):
    line_prefix = "  " * indent
    output.append(f"{line_prefix}{func.name}")

    if MAX_DEPTH is not None and depth >= MAX_DEPTH:
        return

    if func.start in call_stack:
        output.append(f"{line_prefix}  (recursive)")
        return

    if func.start in visited:
        return
    visited.add(func.start)

    call_stack.append(func.start)
    for callee in sorted(func.callees, key=lambda f: f.start):
        if not INCLUDE_LIBRARY_FUNCTIONS and callee.symbol.type.name == "ImportAddressSymbol":
            continue
        generate_call_tree(callee, output, indent + 1, visited, depth + 1, call_stack)
    call_stack.pop()

def show_call_tree(bv: BinaryView):
    entry = locate_main(bv)
    if entry is None:
        entry = bv.entry_function or bv.get_function_at(bv.entry_point)
        bv.show_message_box("Call Tree", "Could not find 'main' or 'main.main'. Using entry point instead.")

    result: List[str] = []
    generate_call_tree(entry, result, 0, set(), 0, [])
    tree_output = "\n".join(result)

    log_info("\n" + tree_output)
    show_plain_text_report("Call Tree (Text)", tree_output)

PluginCommand.register(
    "Call Tree (Text)/From main",
    "Print call tree as plain text (auto-detects main.main)",
    show_call_tree,
)
