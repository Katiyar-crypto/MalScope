"""
MalScope - Control Flow Graph Generator
Generates CFGs from Python bytecode using networkx and graphviz
"""

import dis
import os
import tempfile
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field


@dataclass
class BasicBlock:
    """A basic block in the CFG"""
    id: int
    start_offset: int
    end_offset: int
    instructions: List[Dict] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)
    block_type: str = "normal"  # normal, branch, loop, exception, return


class CFGGenerator:
    """Generates Control Flow Graphs from Python bytecode"""

    BRANCH_OPS = {
        "JUMP_FORWARD", "JUMP_ABSOLUTE", "POP_JUMP_IF_TRUE",
        "POP_JUMP_IF_FALSE", "JUMP_IF_TRUE_OR_POP", "JUMP_IF_FALSE_OR_POP",
        "FOR_ITER", "JUMP_IF_NOT_EXC_MATCH", "POP_JUMP_FORWARD_IF_FALSE",
        "POP_JUMP_FORWARD_IF_TRUE", "POP_JUMP_BACKWARD_IF_FALSE",
        "POP_JUMP_BACKWARD_IF_TRUE", "JUMP_BACKWARD",
    }
    RETURN_OPS = {"RETURN_VALUE", "RETURN_CONST", "RAISE_VARARGS", "RERAISE"}

    def build_cfg(self, code_object) -> Dict[int, BasicBlock]:
        """Build basic blocks from a code object"""
        instructions = list(dis.get_instructions(code_object))
        if not instructions:
            return {}

        # Find block boundaries
        leaders = {0}
        for i, instr in enumerate(instructions):
            if instr.opname in self.BRANCH_OPS:
                # Target of jump is a leader
                if instr.argval is not None and isinstance(instr.argval, int):
                    leaders.add(instr.argval)
                # Next instruction after branch is a leader
                if i + 1 < len(instructions):
                    leaders.add(instructions[i + 1].offset)
            if instr.is_jump_target:
                leaders.add(instr.offset)

        offset_to_index = {instr.offset: idx for idx, instr in enumerate(instructions)}

        # Build blocks
        sorted_leaders = sorted(leaders)
        blocks: Dict[int, BasicBlock] = {}
        block_id = 0

        for idx, leader_offset in enumerate(sorted_leaders):
            end_offset = sorted_leaders[idx + 1] - 1 if idx + 1 < len(sorted_leaders) else float("inf")
            block_instrs = [
                {
                    "offset": instr.offset,
                    "opname": instr.opname,
                    "argrepr": instr.argrepr,
                    "arg": instr.arg,
                    "argval": instr.argval,
                }
                for instr in instructions
                if leader_offset <= instr.offset <= end_offset
            ]
            if not block_instrs:
                continue

            last_op = block_instrs[-1]["opname"]
            btype = "normal"
            if last_op in self.RETURN_OPS:
                btype = "return"
            elif last_op in self.BRANCH_OPS:
                btype = "branch"

            block = BasicBlock(
                id=block_id,
                start_offset=leader_offset,
                end_offset=block_instrs[-1]["offset"],
                instructions=block_instrs,
                block_type=btype,
            )
            blocks[block_id] = block
            block_id += 1

        # Build edges
        offset_to_block = {b.start_offset: b.id for b in blocks.values()}

        for b in blocks.values():
            if not b.instructions:
                continue
            last = b.instructions[-1]
            last_op = last["opname"]

            if last_op in self.RETURN_OPS:
                continue

            if last_op in self.BRANCH_OPS:
                # Conditional: fall-through + jump target
                jump_target = last.get("argval")
                if isinstance(jump_target, int) and jump_target in offset_to_block:
                    target_id = offset_to_block[jump_target]
                    b.successors.append(target_id)
                    blocks[target_id].predecessors.append(b.id)

            # Fall-through to next block based on the actual next instruction
            next_offset = None
            last_index = offset_to_index.get(last["offset"])
            if last_index is not None and last_index + 1 < len(instructions):
                next_offset = instructions[last_index + 1].offset

            if next_offset is not None and next_offset in offset_to_block and last_op not in {"JUMP_FORWARD", "JUMP_ABSOLUTE", "JUMP_BACKWARD"}:
                next_id = offset_to_block[next_offset]
                if next_id not in b.successors:
                    b.successors.append(next_id)
                    blocks[next_id].predecessors.append(b.id)

        return blocks

    def to_dot(self, blocks: Dict[int, BasicBlock], func_name: str = "main") -> str:
        """Convert CFG to Graphviz DOT format"""
        COLOR_MAP = {
            "normal": "#1e2a3a",
            "branch": "#2a1a3a",
            "return": "#1a3a1a",
            "exception": "#3a1a1a",
        }
        BORDER_MAP = {
            "normal": "#4fc3f7",
            "branch": "#ce93d8",
            "return": "#81c784",
            "exception": "#ef9a9a",
        }

        lines = [
            f'digraph "{func_name}" {{',
            '    graph [bgcolor="#0d1117" fontname="Consolas" rankdir=TB splines=curved];',
            '    node [shape=box style="filled,rounded" fontname="Consolas" fontsize=9 fontcolor="#e0e0e0"];',
            '    edge [color="#555555" fontname="Consolas" fontsize=8 fontcolor="#aaaaaa"];',
        ]

        for bid, block in blocks.items():
            instr_lines = []
            for instr in block.instructions[:8]:  # Limit instructions shown
                line = f'{instr["offset"]:4d}  {instr["opname"]:<24} {instr["argrepr"]}'
                instr_lines.append(line.replace('"', "'").replace('\\', '/'))
            if len(block.instructions) > 8:
                instr_lines.append(f"    ... +{len(block.instructions)-8} more")

            label = f"Block {bid}\\l" + "\\l".join(instr_lines) + "\\l"
            fill = COLOR_MAP.get(block.block_type, "#1e2a3a")
            border = BORDER_MAP.get(block.block_type, "#4fc3f7")
            lines.append(f'    {bid} [label="{label}" fillcolor="{fill}" color="{border}"];')

        for bid, block in blocks.items():
            for sid in block.successors:
                edge_color = "#ce93d8" if block.block_type == "branch" else "#4fc3f7"
                lines.append(f'    {bid} -> {sid} [color="{edge_color}"];')

        lines.append("}")
        return "\n".join(lines)

    def generate_graph_image(self, code_object, output_path: str,
                              func_name: str = "main", fmt: str = "png") -> bool:
        """Generate CFG image using Graphviz"""
        try:
            import graphviz
            blocks = self.build_cfg(code_object)
            dot_source = self.to_dot(blocks, func_name)
            graph = graphviz.Source(dot_source)
            base = output_path.replace(f".{fmt}", "")
            graph.render(base, format=fmt, cleanup=True)
            return True
        except ImportError:
            # Try system graphviz via subprocess
            return self._generate_via_subprocess(code_object, output_path, func_name, fmt)
        except Exception:
            return False

    def _generate_via_subprocess(self, code_object, output_path: str,
                                  func_name: str, fmt: str) -> bool:
        import subprocess
        try:
            blocks = self.build_cfg(code_object)
            dot_source = self.to_dot(blocks, func_name)
            with tempfile.NamedTemporaryFile(mode="w", suffix=".dot", delete=False) as f:
                f.write(dot_source)
                dot_file = f.name

            result = subprocess.run(
                ["dot", f"-T{fmt}", dot_file, "-o", output_path],
                capture_output=True, timeout=10
            )
            os.unlink(dot_file)
            return result.returncode == 0
        except Exception:
            return False

    def get_cfg_summary(self, blocks: Dict[int, BasicBlock]) -> Dict:
        """Get high-level CFG statistics"""
        return {
            "total_blocks": len(blocks),
            "branch_blocks": sum(1 for b in blocks.values() if b.block_type == "branch"),
            "return_blocks": sum(1 for b in blocks.values() if b.block_type == "return"),
            "total_edges": sum(len(b.successors) for b in blocks.values()),
            "cyclomatic_complexity": sum(len(b.successors) for b in blocks.values()) - len(blocks) + 2,
        }
