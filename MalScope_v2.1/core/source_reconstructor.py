"""
MalScope - Python 3.11 Source Reconstructor
Reconstructs readable Python source from bytecode instruction streams.
"""

import dis
import marshal
import struct
from typing import List, Dict, Optional, Any


class SourceReconstructor:
    LOAD_OPS = {
        "LOAD_CONST","LOAD_NAME","LOAD_GLOBAL","LOAD_FAST","LOAD_DEREF",
        "LOAD_ATTR","LOAD_METHOD","LOAD_BUILD_CLASS","LOAD_CLOSURE",
        "LOAD_CLASSDEREF","LOAD_SUPER_ATTR","LOAD_FROM_DICT_OR_DEREF",
        "LOAD_FROM_DICT_OR_GLOBALS","LOAD_FAST_BORROW",
    }
    STORE_OPS = {"STORE_NAME","STORE_FAST","STORE_GLOBAL","STORE_DEREF","STORE_ATTR","STORE_SUBSCR"}
    IMPORT_OPS = {"IMPORT_NAME","IMPORT_FROM","IMPORT_STAR"}
    CALL_OPS = {
        "CALL","CALL_FUNCTION","CALL_FUNCTION_KW","CALL_FUNCTION_EX",
        "CALL_METHOD","CALL_PY_GENERAL","CALL_KW_BOUND_METHOD","CALL_KW",
        "CALL_PY_WITH_DEFAULTS","CALL_INTRINSIC_1",
    }
    RETURN_OPS = {"RETURN_VALUE","RETURN_CONST"}
    JUMP_OPS = {
        "JUMP_FORWARD","JUMP_ABSOLUTE","JUMP_BACKWARD","POP_JUMP_IF_TRUE",
        "POP_JUMP_IF_FALSE","POP_JUMP_IF_NONE","POP_JUMP_IF_NOT_NONE",
        "JUMP_IF_TRUE_OR_POP","JUMP_IF_FALSE_OR_POP","POP_JUMP_FORWARD_IF_TRUE",
        "POP_JUMP_FORWARD_IF_FALSE","POP_JUMP_FORWARD_IF_NONE",
        "POP_JUMP_FORWARD_IF_NOT_NONE","FOR_ITER","FOR_ITER_GEN",
    }

    def reconstruct(self, co, indent: int = 0) -> str:
        lines = self._process_code_object(co, indent=indent, is_module=True)
        return "\n".join(lines)

    def _process_code_object(self, co, indent=0, is_module=False, func_name="", func_args=""):
        pad = "    " * indent
        lines = []
        instrs = list(dis.get_instructions(co))
        sub_codes = {c.co_name: c for c in co.co_consts if hasattr(c, "co_code")}
        by_line = self._group_by_line(instrs)
        emitted_imports, emitted_funcs = {}, {}

        if not is_module and func_name:
            lines.append(f"{pad}def {func_name}({func_args}):")
            if not by_line:
                lines.append(f"{pad}    pass")

        for lineno in sorted(by_line.keys()):
            group = by_line[lineno]
            inner_pad = pad if is_module else pad + "    "
            line_src = self._reconstruct_line(group, co, sub_codes, inner_pad, emitted_imports, emitted_funcs, indent)
            if line_src:
                lines.extend(line_src)

        for name, sub_co in sub_codes.items():
            if name not in emitted_funcs and name not in ("<listcomp>","<dictcomp>","<genexpr>","<lambda>"):
                lines.append("")
                lines.extend(self._emit_function(name, sub_co, indent + (0 if is_module else 1)))
                emitted_funcs[name] = True
        return lines

    def _reconstruct_line(self, instrs, co, sub_codes, pad, emitted_imports, emitted_funcs, indent):
        opnames = [i.opname for i in instrs]
        if "IMPORT_NAME" in opnames:
            return self._reconstruct_import(instrs, pad, emitted_imports)
        if "LOAD_BUILD_CLASS" in opnames:
            return self._reconstruct_class(instrs, sub_codes, pad, emitted_funcs, indent)
        if "MAKE_FUNCTION" in opnames:
            return self._reconstruct_function(instrs, sub_codes, pad, emitted_funcs, indent)
        if any(i.opname in self.RETURN_OPS for i in instrs):
            return self._reconstruct_return(instrs, pad)
        if any(i.opname in ("GET_ITER","FOR_ITER","FOR_ITER_GEN") for i in instrs):
            return self._reconstruct_for(instrs, pad)
        if any(i.opname in self.JUMP_OPS for i in instrs):
            return self._reconstruct_conditional(instrs, pad)
        if any(i.opname in self.STORE_OPS for i in instrs):
            return self._reconstruct_assignment(instrs, pad)
        if any(i.opname in self.CALL_OPS for i in instrs):
            expr = self._reconstruct_call_expr(instrs)
            if expr:
                return [f"{pad}{expr}"]
        if any(i.opname == "RAISE_VARARGS" for i in instrs):
            args = [i for i in instrs if i.opname in self.LOAD_OPS]
            return [f"{pad}raise {args[0].argrepr if args else 'Exception()'}"]
        if any(i.opname in ("DELETE_NAME","DELETE_FAST","DELETE_GLOBAL") for i in instrs):
            for i in instrs:
                if i.opname.startswith("DELETE_"):
                    return [f"{pad}del {i.argrepr}"]
        if any(i.opname in ("YIELD_VALUE","SEND") for i in instrs):
            loads = [i for i in instrs if i.opname in self.LOAD_OPS]
            return [f"{pad}yield {loads[0].argrepr if loads else 'value'}"]
        return None

    def _reconstruct_import(self, instrs, pad, emitted):
        out = []
        i = 0
        while i < len(instrs):
            instr = instrs[i]
            if instr.opname == "IMPORT_NAME":
                mod = instr.argval
                from_names = []
                j = i + 1
                while j < len(instrs) and instrs[j].opname == "IMPORT_FROM":
                    from_names.append(instrs[j].argval)
                    j += 1
                key = f"{mod}:{','.join(from_names)}"
                if key not in emitted:
                    emitted[key] = True
                    if from_names:
                        out.append(f"{pad}from {mod} import {', '.join(from_names)}")
                    else:
                        out.append(f"{pad}import {mod}")
            i += 1
        return out or None

    def _reconstruct_class(self, instrs, sub_codes, pad, emitted_funcs, indent):
        name = None
        bases = []
        for instr in instrs:
            if instr.opname == "LOAD_CONST" and isinstance(instr.argval, str):
                name = instr.argval
            if instr.opname == "LOAD_NAME" and instr.argval not in ("__build_class__",):
                bases.append(instr.argval)
        if not name:
            name = "UnknownClass"
        base_str = f"({', '.join(bases)})" if bases else ""
        lines = ["", f"{pad}class {name}{base_str}:"]
        if name in sub_codes:
            emitted_funcs[name] = True
            body = self._process_code_object(sub_codes[name], indent=indent+1, is_module=True)
            lines.extend(body if body else [f"{pad}    pass"])
        else:
            lines.append(f"{pad}    pass")
        lines.append("")
        return lines

    def _reconstruct_function(self, instrs, sub_codes, pad, emitted_funcs, indent):
        name = None
        for instr in instrs:
            if instr.opname in ("STORE_NAME","STORE_FAST"):
                name = instr.argval; break
        if not name:
            for instr in instrs:
                if instr.opname == "LOAD_CONST" and isinstance(instr.argval, str):
                    name = instr.argval; break
        if not name or name not in sub_codes:
            for fname in sub_codes:
                if fname not in emitted_funcs and fname != "<module>":
                    name = fname; break
        if not name or name not in sub_codes:
            return None
        emitted_funcs[name] = True
        return [""] + self._emit_function(name, sub_codes[name], indent)

    def _emit_function(self, name, co, indent):
        pad = "    " * indent
        argcount = co.co_argcount
        varnames = list(co.co_varnames)
        args = varnames[:argcount]
        has_vargs = bool(co.co_flags & 0x04)
        has_vkw = bool(co.co_flags & 0x08)
        is_async = bool(co.co_flags & 0x100)
        if has_vargs and argcount < len(varnames):
            args.append("*" + varnames[argcount])
        if has_vkw:
            kw_idx = argcount + (1 if has_vargs else 0)
            if kw_idx < len(varnames):
                args.append("**" + varnames[kw_idx])
        prefix = "async " if is_async else ""
        lines = [f"{pad}{prefix}def {name}({', '.join(args)}):"]
        if co.co_consts and isinstance(co.co_consts[0], str) and co.co_consts[0].strip():
            doc = co.co_consts[0].replace('"', '\\"')
            lines.append(f'{pad}    """{doc}"""')
        body = self._process_code_object(co, indent=indent+1, is_module=True)
        lines.extend(body if body else [f"{pad}    pass"])
        lines.append("")
        return lines

    def _reconstruct_return(self, instrs, pad):
        expr = self._build_expr(instrs)
        return [f"{pad}return {expr or 'None'}"]

    def _reconstruct_for(self, instrs, pad):
        loads = [i for i in instrs if i.opname in self.LOAD_OPS and i.argrepr]
        stores = [i for i in instrs if i.opname in self.STORE_OPS]
        return [f"{pad}for {stores[0].argrepr if stores else '_item'} in {loads[0].argrepr if loads else 'iterable'}:"]

    def _reconstruct_conditional(self, instrs, pad):
        loads = [i for i in instrs if i.opname in self.LOAD_OPS and i.argrepr]
        cmp = next((i for i in instrs if i.opname == "COMPARE_OP"), None)
        jump = next((i for i in instrs if i.opname in self.JUMP_OPS), None)
        if len(loads) >= 2 and cmp:
            cond = f"{loads[0].argrepr} {cmp.argrepr} {loads[1].argrepr}"
        elif loads:
            neg = "not " if jump and "FALSE" in jump.opname else ""
            cond = f"{neg}{loads[0].argrepr}"
        else:
            cond = "condition"
        return [f"{pad}if {cond}:"]

    def _reconstruct_assignment(self, instrs, pad):
        stores = [i for i in instrs if i.opname in self.STORE_OPS]
        if not stores:
            return []
        target = stores[0].argrepr or stores[0].argval or "_var"
        rhs = self._build_expr(instrs)
        return [f"{pad}{target} = {rhs}"] if rhs else []

    def _reconstruct_call_expr(self, instrs):
        func_name = None
        args_parts = []
        for instr in instrs:
            if instr.opname in ("PUSH_NULL","RESUME","COPY_FREE_VARS"): continue
            if instr.opname in self.LOAD_OPS and func_name is None:
                func_name = instr.argrepr or str(instr.argval)
            elif instr.opname == "LOAD_ATTR":
                func_name = f"{func_name}.{instr.argrepr}" if func_name else instr.argrepr
            elif instr.opname in self.LOAD_OPS and instr.argrepr:
                args_parts.append(instr.argrepr)
            elif instr.opname in self.CALL_OPS:
                break
        return f"{func_name}({', '.join(args_parts)})" if func_name else None

    def _build_expr(self, instrs):
        stack = []
        for instr in instrs:
            if instr.opname in self.STORE_OPS: break
            if instr.opname == "LOAD_CONST": stack.append(repr(instr.argval))
            elif instr.opname in self.LOAD_OPS and instr.argrepr: stack.append(instr.argrepr)
            elif instr.opname == "LOAD_ATTR" and stack: stack[-1] = f"{stack[-1]}.{instr.argrepr}"
            elif instr.opname == "BINARY_OP" and len(stack) >= 2:
                b, a = stack.pop(), stack.pop(); stack.append(f"{a} {instr.argrepr} {b}")
            elif instr.opname == "COMPARE_OP" and len(stack) >= 2:
                b, a = stack.pop(), stack.pop(); stack.append(f"{a} {instr.argrepr} {b}")
            elif instr.opname == "BUILD_LIST":
                n = instr.argval or 0
                items = stack[-n:] if n else []
                stack = stack[:-n] if n else stack
                stack.append(f"[{', '.join(items)}]")
            elif instr.opname == "BUILD_TUPLE":
                n = instr.argval or 0
                items = stack[-n:] if n else []
                stack = stack[:-n] if n else stack
                stack.append(f"({', '.join(items)})")
            elif instr.opname in self.CALL_OPS and stack:
                func = stack.pop(0)
                stack = [f"{func}({', '.join(stack)})"]
        return stack[-1] if stack else None

    def _group_by_line(self, instrs):
        groups, current_line = {}, 1
        for instr in instrs:
            ln = None
            if hasattr(instr, "positions") and instr.positions:
                ln = getattr(instr.positions, "lineno", None)
            if ln is None:
                ln = getattr(instr, "starts_line", None)
                if ln is not None: current_line = ln
                ln = current_line
            groups.setdefault(ln, []).append(instr)
        return groups


def reconstruct_from_pyc(filepath: str) -> str:
    try:
        with open(filepath, "rb") as f:
            magic_raw = f.read(4)
            magic = struct.unpack("<H", magic_raw[:2])[0]
            f.read(12) if magic >= 3400 else f.read(8)
            bytecode = f.read()
        code_obj = marshal.loads(bytecode)
        rec = SourceReconstructor()
        source = rec.reconstruct(code_obj)
        header = (
            "# ─────────────────────────────────────────────────────────────\n"
            "# MalScope: Reconstructed Python source (Python 3.11)\n"
            "# Variable/string names preserved from bytecode.\n"
            "# ─────────────────────────────────────────────────────────────\n\n"
        )
        return header + source
    except Exception as e:
        return f"# Source reconstruction failed: {e}"
