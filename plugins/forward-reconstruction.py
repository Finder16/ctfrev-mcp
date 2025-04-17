from __future__ import annotations
import json
import urllib.request
from typing import Dict, List, Set
from binaryninja import (
    BinaryView,
    PluginCommand,
    MediumLevelILOperation,
    SymbolType,
    show_plain_text_report,
    log_info,
)

MODEL_NAME = "deepseek-r1:32b"
BASE_URL = "http://127.0.0.1:11434/api/generate"
MAX_ARRAY_LEN = 256
ARRAY_SECTION_NAMES = (".rodata", ".data")
TEMPERATURE = 0.1
MAX_TOKENS = 2048

def query_ollama(prompt: str) -> str:
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": TEMPERATURE,
            "num_predict": MAX_TOKENS,
        },
    }
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        BASE_URL, data=data, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        result = json.loads(resp.read().decode())
    return result["response"].strip()

def collect_constant_arrays(bv: BinaryView, func) -> Dict[str, bytes]:
    arrays: Dict[str, bytes] = {}
    visited: Set[int] = set()
    mlil_ssa = func.mlil.ssa_form

    for block in mlil_ssa:
        for il in block:
            if il.operation == MediumLevelILOperation.MLIL_CONST_PTR:
                addr = il.constant
                if addr in visited:
                    continue
                visited.add(addr)

                sym = bv.get_symbol_at(addr)
                section = bv.get_section_at(addr)
                if section and section.name not in ARRAY_SECTION_NAMES:
                    continue

                end = min(addr + MAX_ARRAY_LEN, section.end if section else addr + MAX_ARRAY_LEN)
                data = bv.read(addr, end - addr)

                nul_pos = data.find(b"\x00")
                if nul_pos != -1:
                    data = data[:nul_pos]

                if data:
                    name = sym.name if sym else f"table_{addr:x}"
                    arrays[name] = data
    return arrays

def format_arrays(arrays: Dict[str, bytes]) -> str:
    lines: List[str] = []
    for name, data in arrays.items():
        if len(data) <= 32:
            hex_str = data.hex()
            lines.append(f"{name} = bytes.fromhex(\"{hex_str}\")  # {len(data)} B")
        else:
            rows = " ".join(f"{b:02x}" for b in data)
            lines.append(f"{name} = bytes.fromhex(\"\"\"\n{rows}\n\"\"\")  # {len(data)} B")
    return "\n".join(lines)

SYSTEM_PROMPT = """
You are an assistant that rewrites BinaryNinja MLIL into clean, constant–
folded Python. Evaluate every operation whose operands are compile-time
constants. Inline small lookup tables if provided. Preserve control-flow
structure but remove dead branches when their conditions are resolved.
Output *only* Python code – no explanation, no markdown.
""".strip()

USER_PROMPT_TMPL = """
# --- MLIL ------------------
{mlil}

# --- constant arrays -------
{arrays}

# --- task ------------------
Rewrite the MLIL above into equivalent, human-readable Python performing the
same computations, but propagate/fold all constants.
"""

def build_prompt(mlil: str, arrays: Dict[str, bytes]) -> str:
    arrays_src = format_arrays(arrays) if arrays else "# (none)"
    return USER_PROMPT_TMPL.format(mlil=mlil, arrays=arrays_src)

def extract_static_ops(bv: BinaryView, func):
    mlil_ssa = func.mlil.ssa_form
    mlil_text = "\n".join(str(il) for block in mlil_ssa for il in block)

    arrays = collect_constant_arrays(bv, func)
    prompt = build_prompt(mlil_text, arrays)
    full_prompt = SYSTEM_PROMPT + "\n\n" + prompt

    try:
        response = query_ollama(full_prompt)
    except Exception as e:
        show_plain_text_report("Static Ops Extractor – Error", str(e))
        return

    arrays_src = format_arrays(arrays)
    final_code = arrays_src + "\n\n" + response if arrays else response

    log_info("\n" + final_code)
    show_plain_text_report("Static Ops Extractor (Result)", final_code)

def extractor_for_func(bv: BinaryView, func):
    extract_static_ops(bv, func)

PluginCommand.register_for_function(
    "Static Ops Extractor/Current Function",
    "Generate constant‑folded Python from the current function",
    extractor_for_func,
)
