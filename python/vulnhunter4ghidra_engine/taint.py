"""Intra-procedural and inter-procedural VEX IR data-flow taint analysis."""
from __future__ import annotations

from dataclasses import dataclass, field
import logging

from .models import Confidence, Sink, SinkType, Source, SourceType, TaintPath
from .rules import GLOBAL_RULES, RuleRegistry, canonical_func_name

logger = logging.getLogger("vulnhunter4ghidra")

# Standard functions that propagate taint from input argument(s) to return value and/or dst buffer
_TAINT_PROPAGATORS: dict[str, tuple[tuple[int, ...], int | None, bool]] = {
    # func_name -> (src_arg_indices, dst_buf_arg_index_or_None, propagates_to_return)
    "atoi": ((0,), None, True),
    "atol": ((0,), None, True),
    "atoll": ((0,), None, True),
    "strtol": ((0,), None, True),
    "strtoul": ((0,), None, True),
    "strtoll": ((0,), None, True),
    "strtoull": ((0,), None, True),
    "ntohl": ((0,), None, True),
    "ntohs": ((0,), None, True),
    "htonl": ((0,), None, True),
    "htons": ((0,), None, True),
    "strdup": ((0,), None, True),
    "strndup": ((0,), None, True),
    "strchr": ((0,), None, True),
    "strrchr": ((0,), None, True),
    "strstr": ((0,), None, True),
    "strtok": ((0,), None, True),
    "strcpy": ((1,), 0, True),
    "strncpy": ((1,), 0, True),
    "strlcpy": ((1,), 0, False),
    "strcat": ((1,), 0, True),
    "strncat": ((1,), 0, True),
    "strlcat": ((1,), 0, False),
    "memcpy": ((1,), 0, True),
    "memmove": ((1,), 0, True),
    "sprintf": ((1, 2, 3, 4), 0, False),
    "snprintf": ((2, 3, 4, 5), 0, False),
}


@dataclass(frozen=True)
class ValSummary:
    """Lightweight abstract value for VEX registers, temporaries, and stack slots."""
    const_val: int | None = None
    stack_base: str | None = None
    stack_off: int | None = None
    ptr_key: str | None = None
    taints: frozenset[int] = frozenset()

    @property
    def is_tainted(self) -> bool:
        return bool(self.taints)

    def with_taints(self, extra: frozenset[int] | set[int]) -> ValSummary:
        if not extra:
            return self
        return ValSummary(
            const_val=self.const_val,
            stack_base=self.stack_base,
            stack_off=self.stack_off,
            ptr_key=self.ptr_key,
            taints=self.taints | frozenset(extra),
        )

    def merge(self, other: ValSummary) -> ValSummary:
        if self == other:
            return self
        return ValSummary(
            const_val=self.const_val if self.const_val == other.const_val else None,
            stack_base=self.stack_base if self.stack_base == other.stack_base else None,
            stack_off=self.stack_off if (
                self.stack_base == other.stack_base and self.stack_off == other.stack_off
            ) else None,
            ptr_key=self.ptr_key if self.ptr_key == other.ptr_key else None,
            taints=self.taints | other.taints,
        )


@dataclass
class BlockState:
    regs: dict[int, ValSummary] = field(default_factory=dict)
    stack_vals: dict[tuple[str, int], ValSummary] = field(default_factory=dict)
    buf_taints: dict[str, frozenset[int]] = field(default_factory=dict)

    def copy(self) -> BlockState:
        return BlockState(
            regs=dict(self.regs),
            stack_vals=dict(self.stack_vals),
            buf_taints=dict(self.buf_taints),
        )

    def merge_from(self, other: BlockState) -> bool:
        changed = False
        for reg_off, val in other.regs.items():
            cur = self.regs.get(reg_off)
            if cur is None:
                self.regs[reg_off] = val
                changed = True
            else:
                merged = cur.merge(val)
                if merged != cur:
                    self.regs[reg_off] = merged
                    changed = True

        for slot, val in other.stack_vals.items():
            cur = self.stack_vals.get(slot)
            if cur is None:
                self.stack_vals[slot] = val
                changed = True
            else:
                merged = cur.merge(val)
                if merged != cur:
                    self.stack_vals[slot] = merged
                    changed = True

        for bkey, tset in other.buf_taints.items():
            cur = self.buf_taints.get(bkey, frozenset())
            union = cur | tset
            if union != cur:
                self.buf_taints[bkey] = union
                changed = True

        return changed


def _is_real_angr_project(project) -> bool:
    return hasattr(project, "factory") and hasattr(project, "arch") and hasattr(project, "loader")


def _sign_extend(val: int, bits: int) -> int:
    mask = (1 << bits) - 1
    val &= mask
    sign_bit = 1 << (bits - 1)
    return (val ^ sign_bit) - sign_bit


def _get_abi_reg_offsets(project) -> tuple[list[int], int | None, int | None, int | None]:
    """Return (arg_reg_offsets, ret_reg_offset, sp_offset, bp_offset) for project.arch."""
    arch = project.arch
    arg_offsets: list[int] = []
    ret_offset: int | None = None

    try:
        import angr.calling_conventions as ccs
        cc_cls = ccs.default_cc(arch.name, platform=project.simos.name if project.simos else None)
        if cc_cls is not None:
            cc = cc_cls(arch)
            for reg_name in getattr(cc, "ARG_REGS", []):
                if reg_name in arch.registers:
                    arg_offsets.append(arch.registers[reg_name][0])
            ret_loc = getattr(cc, "RETURN_VAL", None)
            if ret_loc is not None and hasattr(ret_loc, "reg_name") and ret_loc.reg_name in arch.registers:
                ret_offset = arch.registers[ret_loc.reg_name][0]
    except Exception:
        pass

    if not arg_offsets:
        fallback_names = {
            "AMD64": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
            "X86": ["eax", "edx", "ecx"],
            "AARCH64": ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
            "ARMEL": ["r0", "r1", "r2", "r3"],
            "ARMHF": ["r0", "r1", "r2", "r3"],
        }.get(arch.name, [])
        for rname in fallback_names:
            if rname in arch.registers:
                arg_offsets.append(arch.registers[rname][0])

    if ret_offset is None:
        for rname in ("rax", "eax", "x0", "r0", "v0", "a0"):
            if rname in arch.registers:
                ret_offset = arch.registers[rname][0]
                break

    sp_offset = getattr(arch, "sp_offset", None)
    bp_offset = getattr(arch, "bp_offset", None)
    return arg_offsets, ret_offset, sp_offset, bp_offset


def _is_readonly_const_addr(project, addr: int | None) -> bool:
    """Return True if addr points into a non-writable initialized binary segment/section."""
    if addr is None or addr <= 0x1000:
        return False
    try:
        loader = project.loader
        sec = loader.find_section_containing(addr)
        if sec is not None:
            if not getattr(sec, "is_writable", True):
                return True
            sec_name = getattr(sec, "name", "") or ""
            if any(k in sec_name for k in ("rodata", "cstring", "const", "text")):
                return True
        seg = loader.find_segment_containing(addr)
        if seg is not None and not getattr(seg, "is_writable", True):
            return True
    except Exception:
        pass
    return False


def _read_const_cstring(project, addr: int | None, max_len: int = 128) -> str | None:
    if not _is_readonly_const_addr(project, addr):
        return None
    try:
        raw = project.loader.memory.load(addr, max_len)
        end = raw.find(b"\x00")
        if end != -1:
            raw = raw[:end]
        return raw.decode("latin-1", errors="ignore")
    except Exception:
        return None


def _buf_key_for_val(val: ValSummary) -> str | None:
    if val.stack_base is not None and val.stack_off is not None:
        # Quantize stack buffer key by base & offset
        return f"stack:{val.stack_base}:{val.stack_off}"
    if val.ptr_key is not None:
        return val.ptr_key
    if val.const_val is not None and val.const_val > 0x1000:
        return f"mem:{hex(val.const_val)}"
    return None


def _effective_taints(state: BlockState, val: ValSummary | None) -> frozenset[int]:
    if val is None:
        return frozenset()
    taints = val.taints
    bkey = _buf_key_for_val(val)
    if bkey and bkey in state.buf_taints:
        taints = taints | state.buf_taints[bkey]
    # Also check overlapping stack buffer writes (e.g. write at buf+0, read or pass buf)
    if val.stack_base is not None and val.stack_off is not None:
        for (sbase, soff), sval in state.stack_vals.items():
            if sbase == val.stack_base and val.stack_off <= soff < val.stack_off + 64:
                taints = taints | sval.taints
    return taints


def _eval_vex_expr(expr, state: BlockState, tmps: dict[int, ValSummary], bits: int) -> ValSummary:
    tag = getattr(expr, "tag", "")
    if tag == "Iex_Const":
        return ValSummary(const_val=expr.con.value)
    if tag == "Iex_RdTmp":
        return tmps.get(expr.tmp, ValSummary())
    if tag == "Iex_Get":
        return state.regs.get(expr.offset, ValSummary())
    if tag == "Iex_Unop":
        arg = _eval_vex_expr(expr.args[0], state, tmps, bits)
        return ValSummary(
            const_val=arg.const_val,
            stack_base=arg.stack_base,
            stack_off=arg.stack_off,
            ptr_key=arg.ptr_key,
            taints=arg.taints,
        )
    if tag == "Iex_Binop":
        a0 = _eval_vex_expr(expr.args[0], state, tmps, bits)
        a1 = _eval_vex_expr(expr.args[1], state, tmps, bits)
        op = getattr(expr, "op", "")
        comb_taints = a0.taints | a1.taints
        # Self-XOR / self-SUB clears register to constant 0 and kills taint!
        if ("Xor" in op or "Sub" in op) and expr.args[0] == expr.args[1]:
            return ValSummary(const_val=0)
        if "Add" in op:
            if a0.stack_base is not None and a0.stack_off is not None and a1.const_val is not None:
                delta = _sign_extend(a1.const_val, bits)
                return ValSummary(
                    stack_base=a0.stack_base,
                    stack_off=a0.stack_off + delta,
                    taints=comb_taints,
                )
            if a1.stack_base is not None and a1.stack_off is not None and a0.const_val is not None:
                delta = _sign_extend(a0.const_val, bits)
                return ValSummary(
                    stack_base=a1.stack_base,
                    stack_off=a1.stack_off + delta,
                    taints=comb_taints,
                )
            if a0.const_val is not None and a1.const_val is not None:
                mask = (1 << bits) - 1
                return ValSummary(const_val=(a0.const_val + a1.const_val) & mask, taints=comb_taints)
        elif "Sub" in op:
            if a0.stack_base is not None and a0.stack_off is not None and a1.const_val is not None:
                delta = _sign_extend(a1.const_val, bits)
                return ValSummary(
                    stack_base=a0.stack_base,
                    stack_off=a0.stack_off - delta,
                    taints=comb_taints,
                )
            if a0.const_val is not None and a1.const_val is not None:
                mask = (1 << bits) - 1
                return ValSummary(const_val=(a0.const_val - a1.const_val) & mask, taints=comb_taints)
        return ValSummary(
            ptr_key=a0.ptr_key or a1.ptr_key,
            taints=comb_taints,
        )
    if tag == "Iex_Load":
        addr_val = _eval_vex_expr(expr.addr, state, tmps, bits)
        loaded_taints = _effective_taints(state, addr_val)
        if addr_val.stack_base is not None and addr_val.stack_off is not None:
            slot_val = state.stack_vals.get((addr_val.stack_base, addr_val.stack_off))
            if slot_val is not None:
                return slot_val.with_taints(loaded_taints)
        return ValSummary(taints=loaded_taints)
    if tag == "Iex_ITE":
        t_true = _eval_vex_expr(expr.iftrue, state, tmps, bits)
        t_false = _eval_vex_expr(expr.iffalse, state, tmps, bits)
        return t_true.merge(t_false)
    return ValSummary()


def iter_function_invocations(project, func) -> list[tuple[int, int | None, bool]]:
    """Return all (block_addr, target_func_addr, is_tailcall) invocations in `func`.

    Covers both standard `Ijk_Call` sites and `-O2`/`-Os` tail-call jumpout blocks
    (`Ijk_Boring` jumping directly to another function's entry point).
    """
    invocations: list[tuple[int, int | None, bool]] = []
    seen_blocks: set[int] = set()

    try:
        for site_block_addr in func.get_call_sites():
            target_addr = func.get_call_target(site_block_addr)
            invocations.append((site_block_addr, target_addr, False))
            seen_blocks.add(site_block_addr)
    except Exception:
        pass

    if _is_real_angr_project(project):
        for jnode in getattr(func, "jumpout_sites", ()):
            if jnode.addr in seen_blocks:
                continue
            try:
                irsb = project.factory.block(jnode.addr, size=jnode.size).vex
                if getattr(irsb, "jumpkind", "") == "Ijk_Boring" and getattr(irsb.next, "tag", "") == "Iex_Const":
                    taddr = irsb.next.con.value
                    if taddr != func.addr and taddr in project.kb.functions:
                        invocations.append((jnode.addr, taddr, True))
                        seen_blocks.add(jnode.addr)
            except Exception:
                pass

    return invocations


@dataclass
class CallObservation:
    call_addr: int
    block_addr: int
    callee_name: str
    arg_vals: list[ValSummary]
    arg_taints: list[frozenset[int]]
    return_taints: frozenset[int]
    stack_slot_caps: dict[tuple[str, int], int] = field(default_factory=dict)


def _compute_stack_slot_caps(seen_offsets: dict[str, set[int]]) -> dict[tuple[str, int], int]:
    caps: dict[tuple[str, int], int] = {}
    for base, offsets in seen_offsets.items():
        boundaries = sorted(offsets | {0})
        for i, off in enumerate(boundaries):
            if off < 0 and i + 1 < len(boundaries):
                caps[(base, off)] = boundaries[i + 1] - off
    return caps


def _analyze_function_vex(
    project,
    func,
    sources: list[Source],
    extra_param_taints: dict[int, frozenset[int]] | None = None,
    callee_return_taints: dict[int, frozenset[int]] | None = None,
    registry: RuleRegistry | None = None,
) -> tuple[dict[int, CallObservation], frozenset[int]]:
    """Run forward VEX data-flow propagation on `func`.

    Returns:
        (call_observations_by_callsite_addr, function_return_taints)
    """
    reg = registry or GLOBAL_RULES
    bits = project.arch.bits
    arg_offsets, ret_offset, sp_offset, bp_offset = _get_abi_reg_offsets(project)

    func_graph = func.graph
    entry_state = BlockState()
    if sp_offset is not None:
        entry_state.regs[sp_offset] = ValSummary(stack_base="sp", stack_off=0)
    if bp_offset is not None:
        entry_state.regs[bp_offset] = ValSummary(stack_base="bp", stack_off=0)

    # Seed parameter / argv sources at function entry
    for src in sources:
        if src.source_type in (SourceType.FUNC_PARAM, SourceType.ARGV) and src.param_index is not None:
            if 0 <= src.param_index < len(arg_offsets):
                roff = arg_offsets[src.param_index]
                pkey = f"param:{func.addr}:{src.param_index}"
                tset = frozenset({src.address})
                entry_state.regs[roff] = ValSummary(ptr_key=pkey, taints=tset)
                entry_state.buf_taints[pkey] = tset

    if extra_param_taints:
        for p_idx, tset in extra_param_taints.items():
            if 0 <= p_idx < len(arg_offsets) and tset:
                roff = arg_offsets[p_idx]
                pkey = f"param:{func.addr}:{p_idx}"
                cur = entry_state.regs.get(roff, ValSummary(ptr_key=pkey))
                entry_state.regs[roff] = cur.with_taints(tset)
                entry_state.buf_taints[pkey] = entry_state.buf_taints.get(pkey, frozenset()) | tset

    source_by_call_addr: dict[int, list[Source]] = {}
    for src in sources:
        if src.source_type not in (SourceType.FUNC_PARAM, SourceType.ARGV):
            source_by_call_addr.setdefault(src.address, []).append(src)

    # Resolve callee names for all callsites and -O2 tail-calls in func
    call_target_names: dict[int, tuple[int | None, str, bool]] = {}
    for site_block_addr, target_addr, is_tail in iter_function_invocations(project, func):
        cname = ""
        if target_addr is not None and target_addr in project.kb.functions:
            cname = canonical_func_name(project.kb.functions[target_addr].name)
        call_target_names[site_block_addr] = (target_addr, cname, is_tail)

    node_by_addr = {n.addr: n for n in func_graph.nodes()}
    entry_node = node_by_addr.get(func.addr)
    if entry_node is None and node_by_addr:
        entry_node = min(node_by_addr.values(), key=lambda n: n.addr)
    if entry_node is None:
        return {}, frozenset()

    in_states: dict[int, BlockState] = {entry_node.addr: entry_state}
    worklist: list = [entry_node]
    visit_counts: dict[int, int] = {}
    call_obs: dict[int, CallObservation] = {}
    func_ret_taints: set[int] = set()
    seen_stack_offsets: dict[str, set[int]] = {"bp": set(), "sp": set()}

    while worklist:
        node = worklist.pop(0)
        visits = visit_counts.get(node.addr, 0)
        if visits >= 4:
            continue
        visit_counts[node.addr] = visits + 1

        state = in_states[node.addr].copy()
        tmps: dict[int, ValSummary] = {}
        last_ins_addr = node.addr

        try:
            block = project.factory.block(node.addr, size=node.size)
            irsb = block.vex
        except Exception:
            irsb = None

        if irsb is not None:
            for stmt in irsb.statements:
                stag = getattr(stmt, "tag", "")
                if stag == "Ist_IMark":
                    last_ins_addr = stmt.addr
                elif stag == "Ist_WrTmp":
                    wval = _eval_vex_expr(stmt.data, state, tmps, bits)
                    tmps[stmt.tmp] = wval
                    if wval.stack_base in seen_stack_offsets and wval.stack_off is not None and wval.stack_off < 0:
                        seen_stack_offsets[wval.stack_base].add(wval.stack_off)
                elif stag == "Ist_Put":
                    # Avoid clobbering PC; track general/stack registers
                    if stmt.offset != getattr(project.arch, "ip_offset", -1):
                        val = _eval_vex_expr(stmt.data, state, tmps, bits)
                        if (
                            stmt.offset not in (sp_offset, bp_offset)
                            and val.stack_base in seen_stack_offsets
                            and val.stack_off is not None
                            and val.stack_off < 0
                        ):
                            seen_stack_offsets[val.stack_base].add(val.stack_off)
                        state.regs[stmt.offset] = val
                elif stag == "Ist_Store":
                    addr_val = _eval_vex_expr(stmt.addr, state, tmps, bits)
                    data_val = _eval_vex_expr(stmt.data, state, tmps, bits)
                    if addr_val.stack_base is not None and addr_val.stack_off is not None:
                        state.stack_vals[(addr_val.stack_base, addr_val.stack_off)] = data_val
                        if addr_val.stack_base in seen_stack_offsets and addr_val.stack_off < 0:
                            seen_stack_offsets[addr_val.stack_base].add(addr_val.stack_off)
                    bkey = _buf_key_for_val(addr_val)
                    if bkey and data_val.taints:
                        state.buf_taints[bkey] = state.buf_taints.get(bkey, frozenset()) | data_val.taints

            jumpkind = getattr(irsb, "jumpkind", "")
            is_tailcall_site = node.addr in call_target_names and call_target_names[node.addr][2]
            if jumpkind == "Ijk_Call" or is_tailcall_site:
                call_ins_addr = last_ins_addr
                target_addr, cname, is_tail = call_target_names.get(node.addr, (None, "", False))
                arg_vals = [state.regs.get(roff, ValSummary()) for roff in arg_offsets]
                arg_taints = [_effective_taints(state, av) for av in arg_vals]

                ret_taints: set[int] = set()

                # 1. Source callsites seed return register and output argument buffers
                matched_sources = source_by_call_addr.get(call_ins_addr, [])
                if not matched_sources and node.addr in source_by_call_addr:
                    matched_sources = source_by_call_addr[node.addr]

                for src in matched_sources:
                    origin = frozenset({src.address})
                    spec = reg.sources.get(cname)
                    if spec is None or spec.taints_return:
                        ret_taints.update(origin)
                    out_indices = spec.tainted_out_args if spec is not None else (0, 1)
                    for out_idx in out_indices:
                        if 0 <= out_idx < len(arg_vals):
                            bkey = _buf_key_for_val(arg_vals[out_idx])
                            if bkey:
                                state.buf_taints[bkey] = state.buf_taints.get(bkey, frozenset()) | origin
                            if (
                                arg_vals[out_idx].stack_base is not None
                                and arg_vals[out_idx].stack_off is not None
                            ):
                                slot = (arg_vals[out_idx].stack_base, arg_vals[out_idx].stack_off)
                                cur_slot = state.stack_vals.get(slot, ValSummary())
                                state.stack_vals[slot] = cur_slot.with_taints(origin)

                # 2. Propagators (strdup, atoi, snprintf, strcpy, memcpy, etc.)
                prop = _TAINT_PROPAGATORS.get(cname)
                if prop is not None:
                    src_indices, dst_idx, to_ret = prop
                    combined_in: set[int] = set()
                    for s_idx in src_indices:
                        if 0 <= s_idx < len(arg_taints):
                            combined_in.update(arg_taints[s_idx])
                    if combined_in:
                        if dst_idx is not None and 0 <= dst_idx < len(arg_vals):
                            bkey = _buf_key_for_val(arg_vals[dst_idx])
                            if bkey:
                                state.buf_taints[bkey] = (
                                    state.buf_taints.get(bkey, frozenset()) | frozenset(combined_in)
                                )
                        if to_ret:
                            ret_taints.update(combined_in)

                # 3. Sanitizer functions clear taint on destination argument
                if cname in reg.sanitizers or (target_addr is not None and target_addr in reg.sanitizer_addrs):
                    if arg_vals:
                        bkey = _buf_key_for_val(arg_vals[0])
                        if bkey and bkey in state.buf_taints:
                            del state.buf_taints[bkey]

                # 4. Inter-procedural return taint summary
                if callee_return_taints and target_addr in callee_return_taints:
                    ret_taints.update(callee_return_taints[target_addr])

                # 5. Update return register (or allocator pointer tag)
                if ret_offset is not None:
                    ptr_tag = f"alloc:{hex(call_ins_addr)}" if cname in ("malloc", "calloc", "realloc", "strdup") else None
                    if ret_taints or ptr_tag:
                        state.regs[ret_offset] = ValSummary(
                            ptr_key=ptr_tag,
                            taints=frozenset(ret_taints),
                        )
                    else:
                        state.regs[ret_offset] = ValSummary()

                obs = CallObservation(
                    call_addr=call_ins_addr,
                    block_addr=node.addr,
                    callee_name=cname,
                    arg_vals=arg_vals,
                    arg_taints=arg_taints,
                    return_taints=frozenset(ret_taints),
                )
                call_obs[call_ins_addr] = obs
                call_obs.setdefault(node.addr, obs)

                # Restore stack pointer across call return when architecture's `call` pushes ret addr
                if is_tail:
                    func_ret_taints.update(ret_taints)
                elif sp_offset is not None and getattr(project.arch, "call_pushes_ret", False):
                    sp_val = state.regs.get(sp_offset)
                    if sp_val is not None and sp_val.stack_base is not None and sp_val.stack_off is not None:
                        state.regs[sp_offset] = ValSummary(
                            stack_base=sp_val.stack_base,
                            stack_off=sp_val.stack_off + project.arch.bytes,
                            taints=sp_val.taints,
                        )

            elif jumpkind == "Ijk_Ret" and ret_offset is not None:
                ret_val = state.regs.get(ret_offset)
                func_ret_taints.update(_effective_taints(state, ret_val))

        for succ in func_graph.successors(node):
            succ_state = in_states.get(succ.addr)
            if succ_state is None:
                in_states[succ.addr] = state.copy()
                worklist.append(succ)
            elif succ_state.merge_from(state):
                worklist.append(succ)

    slot_caps = _compute_stack_slot_caps(seen_stack_offsets)
    for obs in call_obs.values():
        obs.stack_slot_caps = slot_caps

    return call_obs, frozenset(func_ret_taints)


def _evaluate_sink_observation(
    project,
    sink: Sink,
    obs: CallObservation,
    allowed_source_addrs: set[int],
    registry: RuleRegistry | None = None,
) -> tuple[set[int], Confidence, list[str], Sink | None]:
    """Validate whether a Sink callsite is genuinely reached by tainted data.

    Returns:
        (matching_source_addrs, confidence, evidence, effective_sink_or_None)
    """
    reg = registry or GLOBAL_RULES
    spec = reg.sinks.get(sink.callee_name)

    # Free / deallocator callsites are handled by stateful UAF/Double-Free detectors in P2,
    # unless explicitly marked as a custom sink.
    if sink.sink_type == SinkType.USE_AFTER_FREE and sink.address not in reg.custom_sink_addrs:
        return set(), Confidence.LOW, [], None

    # 1. Constant argument suppression (e.g., printf("const %s", x) or system("ls"))
    if spec is not None and spec.requires_non_const_arg is not None:
        req_idx = spec.requires_non_const_arg
        if 0 <= req_idx < len(obs.arg_vals):
            req_val = obs.arg_vals[req_idx]
            if _is_readonly_const_addr(project, req_val.const_val):
                # Special case: unbounded sprintf(dst, "prefix %s", tainted_buf) is CWE-120, not CWE-134!
                if sink.callee_name == "sprintf":
                    fmt_str = _read_const_cstring(project, req_val.const_val) or ""
                    if "%s" in fmt_str:
                        vararg_taints: set[int] = set()
                        for v_idx in range(2, len(obs.arg_taints)):
                            vararg_taints.update(obs.arg_taints[v_idx] & allowed_source_addrs)
                        if vararg_taints:
                            upgraded_sink = Sink(
                                address=sink.address,
                                func_addr=sink.func_addr,
                                func_name=sink.func_name,
                                callee_name=sink.callee_name,
                                sink_type=SinkType.BUFFER_OVERFLOW,
                                cwe="CWE-120",
                                vulnerable_arg_index=2,
                                tainted_arg_indices=(2, 3),
                                is_fortified=sink.is_fortified,
                            )
                            return (
                                vararg_taints,
                                Confidence.MEDIUM if sink.is_fortified else Confidence.HIGH,
                                [f"Constant format '{fmt_str}' has unbounded %s with tainted argument"],
                                upgraded_sink,
                            )
                return set(), Confidence.LOW, [], None

    # 2. Safe bounded copy/read suppression:
    # e.g. `char buf[64]; recv(fd, buf, 64, 0)` or `memcpy(dst, src, 16)` where size <= stack slot capacity
    if sink.callee_name in ("memcpy", "memmove", "strncpy", "read", "recv", "recvfrom"):
        dst_idx = 1 if sink.callee_name in ("read", "recv", "recvfrom") else 0
        len_idx = 2
        if len_idx < len(obs.arg_vals) and dst_idx < len(obs.arg_vals):
            len_val = obs.arg_vals[len_idx]
            len_taints = obs.arg_taints[len_idx] & allowed_source_addrs
            dst_val = obs.arg_vals[dst_idx]
            if not len_taints and len_val.const_val is not None:
                # If copy size is constant and fits within the inferred stack slot capacity, suppress!
                if dst_val.stack_base is not None and dst_val.stack_off is not None and dst_val.stack_off < 0:
                    slot_cap = obs.stack_slot_caps.get((dst_val.stack_base, dst_val.stack_off))
                    if slot_cap is not None and 0 <= len_val.const_val <= slot_cap:
                        return set(), Confidence.LOW, [], None
                # Also suppress `memcpy(dst, "const", 5)` where both src and len are constant
                if sink.callee_name in ("memcpy", "memmove", "strncpy") and 1 < len(obs.arg_vals):
                    if _is_readonly_const_addr(project, obs.arg_vals[1].const_val):
                        return set(), Confidence.LOW, [], None

    # 3. Check tainted arguments matching `effective_tainted_args()`
    matched_origins: set[int] = set()
    tainted_arg_hits: list[int] = []
    for arg_idx in sink.effective_tainted_args():
        if 0 <= arg_idx < len(obs.arg_taints):
            overlap = obs.arg_taints[arg_idx] & allowed_source_addrs
            if overlap:
                matched_origins.update(overlap)
                tainted_arg_hits.append(arg_idx)

    if not matched_origins:
        return set(), Confidence.LOW, [], None

    conf = Confidence.MEDIUM if sink.is_fortified else Confidence.HIGH
    evidence = [
        f"VEX data-flow confirmed taint in {sink.callee_name}() arg {tainted_arg_hits}"
    ]
    if sink.is_fortified:
        evidence.append("Target uses fortified *_chk wrapper (bounds check may mitigate if object size known)")
    return matched_origins, conf, evidence, sink


def find_taint_paths_intraprocedural(
    project,
    func_addr: int,
    sources: list[Source],
    sinks: list[Sink],
    registry: RuleRegistry | None = None,
) -> list[TaintPath]:
    """Find taint paths within a single function.

    Uses VEX IR register + stack data-flow tracking on real angr projects,
    falling back to CFG reachability when VEX blocks are unavailable (e.g. unit-test mocks).
    """
    if not sources or not sinks:
        return []

    cfg = project.kb.cfgs.get_most_accurate()
    if cfg is None and hasattr(project, "analyses"):
        cfg = project.analyses.CFGFast(
            regions=[(func_addr, func_addr + 0x10000)],
            normalize=True,
            show_progressbar=False,
        )

    func = project.kb.functions.get(func_addr)
    if func is None:
        logger.warning("Function at %#x not found in KB", func_addr)
        return []

    func_graph = func.graph
    node_map: dict[int, object] = {node.addr: node for node in func_graph.nodes()}

    use_vex = _is_real_angr_project(project)
    call_obs: dict[int, CallObservation] = {}
    if use_vex:
        call_obs, _ = _analyze_function_vex(project, func, sources, registry=registry)

    source_by_addr = {s.address: s for s in sources}
    paths: list[TaintPath] = []

    for sink in sinks:
        snk_node = _find_nearest_node(node_map, sink.address, func_graph)
        if snk_node is None:
            continue

        candidate_sources: list[Source] = []
        for source in sources:
            if source.address == sink.address:
                continue
            src_node = _find_nearest_node(node_map, source.address, func_graph)
            if src_node is None:
                continue
            if src_node == snk_node:
                has_cycle = any(
                    _is_reachable(func_graph, succ, snk_node)
                    for succ in func_graph.successors(src_node)
                )
                if source.address < sink.address or has_cycle:
                    candidate_sources.append(source)
            elif _is_reachable(func_graph, src_node, snk_node):
                candidate_sources.append(source)

        if not candidate_sources:
            continue

        if use_vex:
            obs = call_obs.get(sink.address) or call_obs.get(snk_node.addr)
            if obs is None:
                continue
            allowed = {s.address for s in candidate_sources}
            matched_addrs, conf, evidence, effective_sink = _evaluate_sink_observation(
                project, sink, obs, allowed, registry=registry,
            )
            if not matched_addrs or effective_sink is None:
                continue

            for src_addr in sorted(matched_addrs):
                source = source_by_addr[src_addr]
                src_node = _find_nearest_node(node_map, source.address, func_graph)
                path_addrs = (
                    [src_node.addr]
                    if src_node == snk_node
                    else _extract_path_addrs(func_graph, src_node, snk_node)
                )
                paths.append(TaintPath(
                    source=source,
                    sink=effective_sink,
                    path_addrs=path_addrs,
                    path_funcs=[func.name],
                    confidence=conf,
                    evidence=list(evidence),
                ))
        else:
            for source in candidate_sources:
                src_node = _find_nearest_node(node_map, source.address, func_graph)
                path_addrs = (
                    [src_node.addr]
                    if src_node == snk_node
                    else _extract_path_addrs(func_graph, src_node, snk_node)
                )
                paths.append(TaintPath(
                    source=source,
                    sink=sink,
                    path_addrs=path_addrs,
                    path_funcs=[func.name],
                    confidence=Confidence.LOW,
                    evidence=["CFG basic-block reachability"],
                ))

    return paths


def find_taint_paths_interprocedural(
    project,
    sources: list[Source],
    sinks: list[Sink],
    max_depth: int = 5,
    registry: RuleRegistry | None = None,
) -> list[TaintPath]:
    """Find taint paths across function boundaries.

    On real angr projects, verifies argument-to-parameter taint transfer across
    callsites along the call chain. Falls back to callgraph BFS on mock objects.
    """
    if not sources or not sinks:
        return []

    cfg = project.kb.cfgs.get_most_accurate()
    if cfg is None and hasattr(project, "analyses"):
        cfg = project.analyses.CFGFast(normalize=True, show_progressbar=False)

    call_graph = project.kb.callgraph
    use_vex = _is_real_angr_project(project)

    source_funcs: dict[int, list[Source]] = {}
    for s in sources:
        source_funcs.setdefault(s.func_addr, []).append(s)

    sink_funcs: dict[int, list[Sink]] = {}
    for s in sinks:
        sink_funcs.setdefault(s.func_addr, []).append(s)

    # Precompute return-taint summaries for helper functions that directly invoke sources
    callee_ret_summaries: dict[int, frozenset[int]] = {}
    if use_vex:
        for src_faddr, f_sources in source_funcs.items():
            f_obj = project.kb.functions.get(src_faddr)
            if f_obj is not None:
                _, ret_taints = _analyze_function_vex(
                    project, f_obj, f_sources, registry=registry,
                )
                if ret_taints:
                    callee_ret_summaries[src_faddr] = ret_taints

    paths: list[TaintPath] = []

    # Case A: Source in caller -> passed via arguments down call chain -> Sink in callee
    for src_func_addr, func_sources in source_funcs.items():
        reachable = _bfs_reachable_funcs(call_graph, src_func_addr, max_depth)
        for snk_func_addr, func_sinks in sink_funcs.items():
            if snk_func_addr == src_func_addr or snk_func_addr not in reachable:
                continue
            func_path = reachable[snk_func_addr]
            func_names = []
            for addr in func_path:
                f = project.kb.functions.get(addr)
                func_names.append(f.name if f else hex(addr))

            if not use_vex:
                for source in func_sources:
                    for sink in func_sinks:
                        paths.append(TaintPath(
                            source=source,
                            sink=sink,
                            path_addrs=func_path,
                            path_funcs=func_names,
                            confidence=Confidence.LOW,
                            evidence=["Call-graph reachability"],
                        ))
                continue

            verified_inter = _verify_interprocedural_chain_vex(
                project,
                func_path,
                func_names,
                func_sources,
                func_sinks,
                callee_ret_summaries,
                registry=registry,
            )
            paths.extend(verified_inter)

    # Case B: Source inside helper returns tainted buffer to caller -> caller invokes Sink
    if use_vex and callee_ret_summaries:
        source_lookup = {s.address: s for s in sources}
        for snk_func_addr, func_sinks in sink_funcs.items():
            caller_func = project.kb.functions.get(snk_func_addr)
            if caller_func is None:
                continue
            caller_sources = source_funcs.get(snk_func_addr, [])
            call_obs, _ = _analyze_function_vex(
                project,
                caller_func,
                caller_sources,
                callee_return_taints=callee_ret_summaries,
                registry=registry,
            )
            helper_origins = set().union(*callee_ret_summaries.values())
            for sink in func_sinks:
                obs = call_obs.get(sink.address)
                if obs is None:
                    continue
                matched, conf, ev, eff_sink = _evaluate_sink_observation(
                    project, sink, obs, helper_origins, registry=registry,
                )
                if not matched or eff_sink is None:
                    continue
                for origin_addr in sorted(matched):
                    src = source_lookup.get(origin_addr)
                    if src is None or src.func_addr == snk_func_addr:
                        continue
                    paths.append(TaintPath(
                        source=src,
                        sink=eff_sink,
                        path_addrs=[src.func_addr, snk_func_addr],
                        path_funcs=[src.func_name, caller_func.name],
                        confidence=conf,
                        evidence=ev + [f"Tainted return value from {src.func_name}()"],
                    ))

    return paths


def _verify_interprocedural_chain_vex(
    project,
    func_path: list[int],
    func_names: list[str],
    entry_sources: list[Source],
    leaf_sinks: list[Sink],
    callee_ret_summaries: dict[int, frozenset[int]],
    registry: RuleRegistry | None = None,
) -> list[TaintPath]:
    """Propagate parameter taint step-by-step along `func_path` using VEX."""
    param_taints: dict[int, frozenset[int]] = {}
    source_by_addr = {s.address: s for s in entry_sources}

    for idx in range(len(func_path) - 1):
        cur_addr = func_path[idx]
        next_addr = func_path[idx + 1]
        cur_func = project.kb.functions.get(cur_addr)
        if cur_func is None:
            return []

        cur_sources = entry_sources if idx == 0 else []
        call_obs, _ = _analyze_function_vex(
            project,
            cur_func,
            cur_sources,
            extra_param_taints=param_taints if idx > 0 else None,
            callee_return_taints=callee_ret_summaries,
            registry=registry,
        )

        next_param_taints: dict[int, set[int]] = {}
        for site_block_addr, target_addr, _ in iter_function_invocations(project, cur_func):
            if target_addr != next_addr:
                continue
            obs = call_obs.get(site_block_addr)
            if obs is None:
                continue
            for p_idx, tset in enumerate(obs.arg_taints):
                if tset:
                    next_param_taints.setdefault(p_idx, set()).update(tset)

        if not next_param_taints:
            return []
        param_taints = {k: frozenset(v) for k, v in next_param_taints.items()}

    leaf_func = project.kb.functions.get(func_path[-1])
    if leaf_func is None:
        return []

    leaf_obs, _ = _analyze_function_vex(
        project,
        leaf_func,
        [],
        extra_param_taints=param_taints,
        callee_return_taints=callee_ret_summaries,
        registry=registry,
    )

    allowed = set(source_by_addr.keys())
    confirmed: list[TaintPath] = []
    for sink in leaf_sinks:
        obs = leaf_obs.get(sink.address)
        if obs is None:
            # Try nearest block address
            node_map = {n.addr: n for n in leaf_func.graph.nodes()}
            snk_node = _find_nearest_node(node_map, sink.address, leaf_func.graph)
            if snk_node is not None:
                obs = leaf_obs.get(snk_node.addr)
        if obs is None:
            continue

        matched, conf, ev, eff_sink = _evaluate_sink_observation(
            project, sink, obs, allowed, registry=registry,
        )
        if not matched or eff_sink is None:
            continue

        for src_addr in sorted(matched):
            src = source_by_addr[src_addr]
            confirmed.append(TaintPath(
                source=src,
                sink=eff_sink,
                path_addrs=list(func_path),
                path_funcs=list(func_names),
                confidence=conf,
                evidence=ev + [f"Inter-procedural argument flow: {' -> '.join(func_names)}"],
            ))
    return confirmed


def collect_interprocedural_param_taints(
    project,
    sources: list[Source],
    max_depth: int = 5,
    registry: RuleRegistry | None = None,
) -> dict[int, dict[int, frozenset[int]]]:
    """Propagate tainted call arguments across the callgraph up to `max_depth`.

    Returns:
        {callee_func_addr: {param_index: frozenset(source_addrs)}}
    """
    if not sources or not _is_real_angr_project(project):
        return {}

    source_funcs: dict[int, list[Source]] = {}
    for s in sources:
        source_funcs.setdefault(s.func_addr, []).append(s)

    propagated: dict[int, dict[int, set[int]]] = {}
    frontier: list[tuple[int, int]] = [(faddr, 0) for faddr in source_funcs]
    visited_depth: dict[int, int] = {}

    while frontier:
        cur_addr, depth = frontier.pop(0)
        if depth >= max_depth:
            continue
        prev_d = visited_depth.get(cur_addr)
        if prev_d is not None and prev_d <= depth:
            continue
        visited_depth[cur_addr] = depth

        cur_func = project.kb.functions.get(cur_addr)
        if cur_func is None:
            continue

        in_params = {
            k: frozenset(v) for k, v in propagated.get(cur_addr, {}).items()
        }
        call_obs, _ = _analyze_function_vex(
            project,
            cur_func,
            source_funcs.get(cur_addr, []),
            extra_param_taints=in_params or None,
            registry=registry,
        )

        for site_block, target_addr, _ in iter_function_invocations(project, cur_func):
            if target_addr is None or target_addr not in project.kb.functions:
                continue
            callee_fn = project.kb.functions[target_addr]
            if callee_fn.is_plt or callee_fn.is_simprocedure:
                continue
            obs = call_obs.get(site_block)
            if obs is None:
                continue
            added = False
            for p_idx, tset in enumerate(obs.arg_taints):
                if tset:
                    cur_set = propagated.setdefault(target_addr, {}).setdefault(p_idx, set())
                    before = len(cur_set)
                    cur_set.update(tset)
                    if len(cur_set) > before:
                        added = True
            if added:
                frontier.append((target_addr, depth + 1))

    return {
        faddr: {p_idx: frozenset(origins) for p_idx, origins in pmap.items()}
        for faddr, pmap in propagated.items()
    }


def _find_nearest_node(node_map, addr, graph):
    if addr in node_map:
        return node_map[addr]
    for node in graph.nodes():
        if node.addr <= addr < node.addr + node.size:
            return node
    return None


def _is_reachable(graph, src_node, dst_node) -> bool:
    visited = set()
    queue = [src_node]
    while queue:
        node = queue.pop(0)
        if node == dst_node:
            return True
        if node in visited:
            continue
        visited.add(node)
        for succ in graph.successors(node):
            queue.append(succ)
    return False


def _extract_path_addrs(graph, src_node, dst_node) -> list[int]:
    if src_node == dst_node:
        return [src_node.addr]
    visited = {}
    queue = [src_node]
    visited[src_node] = None
    while queue:
        node = queue.pop(0)
        if node == dst_node:
            path = []
            cur = node
            while cur is not None:
                path.append(cur.addr)
                cur = visited[cur]
            return list(reversed(path))
        for succ in graph.successors(node):
            if succ not in visited:
                visited[succ] = node
                queue.append(succ)
    return [src_node.addr, dst_node.addr]


def _bfs_reachable_funcs(
    call_graph, start_addr: int, max_depth: int
) -> dict[int, list[int]]:
    """BFS over the call graph. Returns {reachable_addr: [path from start]}."""
    reachable = {start_addr: [start_addr]}
    queue = [(start_addr, [start_addr], 0)]
    while queue:
        addr, path, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        try:
            successors = list(call_graph.successors(addr))
        except Exception:
            continue
        for succ in successors:
            if succ not in reachable:
                new_path = path + [succ]
                reachable[succ] = new_path
                queue.append((succ, new_path, depth + 1))
    return reachable
