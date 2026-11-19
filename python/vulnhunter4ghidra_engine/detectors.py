"""Stateful semantic CWE detectors on VEX IR:
- CWE-416: Use-After-Free (dereference or call use of freed pointer without reassignment)
- CWE-415: Double Free (repeated deallocation of freed pointer without reassignment)
- CWE-476: NULL Pointer Dereference (unchecked allocator return dereferenced before branch check)
- CWE-190: Integer Overflow / Wraparound feeding allocation or copy size
- CWE-120: Out-of-bounds write when constant read/fgets/memcpy length exceeds stack frame capacity
"""
from __future__ import annotations

from dataclasses import dataclass, field
import logging

from .models import Confidence, Sink, SinkType, Source, SourceType, TaintPath
from .rules import (
    ALLOCATOR_FUNCTIONS,
    DEALLOCATOR_FUNCTIONS,
    GLOBAL_RULES,
    RuleRegistry,
    canonical_func_name,
)
from .taint import (
    _get_abi_reg_offsets,
    _is_real_angr_project,
    _sign_extend,
    iter_function_invocations,
)

logger = logging.getLogger("vulnhunter4ghidra")

_ARITH_OPS = ("Add", "Mul", "Shl")


@dataclass(frozen=True)
class PtrVal:
    ptr_id: str | None = None
    alloc_addr: int | None = None
    stack_base: str | None = None
    stack_off: int | None = None
    const_val: int | None = None
    taints: frozenset[int] = frozenset()
    arith_tainted: bool = False

    def merge(self, other: PtrVal) -> PtrVal:
        if self == other:
            return self
        return PtrVal(
            ptr_id=self.ptr_id if self.ptr_id == other.ptr_id else None,
            alloc_addr=self.alloc_addr if self.alloc_addr == other.alloc_addr else None,
            stack_base=self.stack_base if self.stack_base == other.stack_base else None,
            stack_off=self.stack_off if (
                self.stack_base == other.stack_base and self.stack_off == other.stack_off
            ) else None,
            const_val=self.const_val if self.const_val == other.const_val else None,
            taints=self.taints | other.taints,
            arith_tainted=self.arith_tainted or other.arith_tainted,
        )


@dataclass
class LifecycleState:
    regs: dict[int, PtrVal] = field(default_factory=dict)
    stack_slots: dict[tuple[str, int], PtrVal] = field(default_factory=dict)
    buf_arith: dict[str, tuple[frozenset[int], bool]] = field(default_factory=dict)
    freed_ptrs: dict[str, int] = field(default_factory=dict)       # ptr_id -> free_call_addr
    unchecked_allocs: dict[str, int] = field(default_factory=dict) # ptr_id -> alloc_call_addr

    def copy(self) -> LifecycleState:
        return LifecycleState(
            regs=dict(self.regs),
            stack_slots=dict(self.stack_slots),
            buf_arith=dict(self.buf_arith),
            freed_ptrs=dict(self.freed_ptrs),
            unchecked_allocs=dict(self.unchecked_allocs),
        )

    def merge_from(self, other: LifecycleState) -> bool:
        changed = False
        for r, v in other.regs.items():
            cur = self.regs.get(r)
            if cur is None:
                self.regs[r] = v
                changed = True
            else:
                m = cur.merge(v)
                if m != cur:
                    self.regs[r] = m
                    changed = True

        for k, v in other.stack_slots.items():
            cur = self.stack_slots.get(k)
            if cur is None:
                self.stack_slots[k] = v
                changed = True
            else:
                m = cur.merge(v)
                if m != cur:
                    self.stack_slots[k] = m
                    changed = True

        for bkey, (tset, ar) in other.buf_arith.items():
            cur_t, cur_ar = self.buf_arith.get(bkey, (frozenset(), False))
            nt, nar = cur_t | tset, cur_ar or ar
            if (nt, nar) != (cur_t, cur_ar):
                self.buf_arith[bkey] = (nt, nar)
                changed = True

        for pid, faddr in other.freed_ptrs.items():
            if pid not in self.freed_ptrs:
                self.freed_ptrs[pid] = faddr
                changed = True

        for pid, aaddr in other.unchecked_allocs.items():
            if pid not in self.unchecked_allocs:
                self.unchecked_allocs[pid] = aaddr
                changed = True

        return changed


def _eval_ptr_expr(expr, state: LifecycleState, tmps: dict[int, PtrVal], bits: int) -> PtrVal:
    tag = getattr(expr, "tag", "")
    if tag == "Iex_Const":
        return PtrVal(const_val=expr.con.value)
    if tag == "Iex_RdTmp":
        return tmps.get(expr.tmp, PtrVal())
    if tag == "Iex_Get":
        return state.regs.get(expr.offset, PtrVal())
    if tag == "Iex_Unop":
        return _eval_ptr_expr(expr.args[0], state, tmps, bits)
    if tag == "Iex_Binop":
        a0 = _eval_ptr_expr(expr.args[0], state, tmps, bits)
        a1 = _eval_ptr_expr(expr.args[1], state, tmps, bits)
        op = getattr(expr, "op", "")
        if ("Xor" in op or "Sub" in op) and expr.args[0] == expr.args[1]:
            return PtrVal(const_val=0)

        comb_taints = a0.taints | a1.taints
        is_arith = a0.arith_tainted or a1.arith_tainted
        if comb_taints and any(k in op for k in _ARITH_OPS):
            # Exclude pointer + stack offset calculation; flag integer math on tainted values
            if a0.stack_base is None and a1.stack_base is None:
                is_arith = True

        if "Add" in op:
            if a0.stack_base is not None and a0.stack_off is not None and a1.const_val is not None:
                return PtrVal(
                    stack_base=a0.stack_base,
                    stack_off=a0.stack_off + _sign_extend(a1.const_val, bits),
                    taints=comb_taints,
                )
            if a1.stack_base is not None and a1.stack_off is not None and a0.const_val is not None:
                return PtrVal(
                    stack_base=a1.stack_base,
                    stack_off=a1.stack_off + _sign_extend(a0.const_val, bits),
                    taints=comb_taints,
                )
        elif "Sub" in op:
            if a0.stack_base is not None and a0.stack_off is not None and a1.const_val is not None:
                return PtrVal(
                    stack_base=a0.stack_base,
                    stack_off=a0.stack_off - _sign_extend(a1.const_val, bits),
                    taints=comb_taints,
                )

        return PtrVal(
            ptr_id=a0.ptr_id or a1.ptr_id,
            alloc_addr=a0.alloc_addr or a1.alloc_addr,
            taints=comb_taints,
            arith_tainted=is_arith,
        )
    if tag == "Iex_Load":
        addr_v = _eval_ptr_expr(expr.addr, state, tmps, bits)
        if addr_v.stack_base is not None and addr_v.stack_off is not None:
            slot = (addr_v.stack_base, addr_v.stack_off)
            if slot in state.stack_slots:
                sv = state.stack_slots[slot]
                bkey = f"stack:{slot[0]}:{slot[1]}"
                bt, bar = state.buf_arith.get(bkey, (frozenset(), False))
                return PtrVal(
                    ptr_id=sv.ptr_id,
                    alloc_addr=sv.alloc_addr,
                    stack_base=sv.stack_base,
                    stack_off=sv.stack_off,
                    const_val=sv.const_val,
                    taints=sv.taints | bt,
                    arith_tainted=sv.arith_tainted or bar,
                )
        return PtrVal(taints=addr_v.taints, arith_tainted=addr_v.arith_tainted)
    return PtrVal()


def detect_semantic_vulns_in_function(
    project,
    func_addr: int,
    sources: list[Source],
    registry: RuleRegistry | None = None,
    extra_param_taints: dict[int, frozenset[int]] | None = None,
    global_source_lookup: dict[int, Source] | None = None,
) -> list[TaintPath]:
    """Run stateful detectors for CWE-415, CWE-416, CWE-476, CWE-190, and stack OOB."""
    if not _is_real_angr_project(project):
        return []

    func = project.kb.functions.get(func_addr)
    if func is None:
        return []

    reg = registry or GLOBAL_RULES
    bits = project.arch.bits
    arg_offsets, ret_offset, sp_offset, bp_offset = _get_abi_reg_offsets(project)

    func_graph = func.graph
    node_by_addr = {n.addr: n for n in func_graph.nodes()}
    entry_node = node_by_addr.get(func.addr) or (
        min(node_by_addr.values(), key=lambda n: n.addr) if node_by_addr else None
    )
    if entry_node is None:
        return []

    init_state = LifecycleState()
    if sp_offset is not None:
        init_state.regs[sp_offset] = PtrVal(stack_base="sp", stack_off=0)
    if bp_offset is not None:
        init_state.regs[bp_offset] = PtrVal(stack_base="bp", stack_off=0)

    source_by_addr = dict(global_source_lookup) if global_source_lookup else {}
    for s in sources:
        source_by_addr[s.address] = s

    source_by_call_addr: dict[int, list[Source]] = {}
    for s in sources:
        if s.source_type in (SourceType.FUNC_PARAM, SourceType.ARGV) and s.param_index is not None:
            if 0 <= s.param_index < len(arg_offsets):
                roff = arg_offsets[s.param_index]
                pid = f"param:{func.addr}:{s.param_index}"
                init_state.regs[roff] = PtrVal(ptr_id=pid, taints=frozenset({s.address}))
        else:
            source_by_call_addr.setdefault(s.address, []).append(s)

    if extra_param_taints:
        for p_idx, tset in extra_param_taints.items():
            if 0 <= p_idx < len(arg_offsets) and tset:
                roff = arg_offsets[p_idx]
                pid = f"param:{func.addr}:{p_idx}"
                cur = init_state.regs.get(roff, PtrVal(ptr_id=pid))
                init_state.regs[roff] = PtrVal(
                    ptr_id=cur.ptr_id or pid,
                    taints=cur.taints | frozenset(tset),
                )

    call_targets: dict[int, tuple[str, bool]] = {}
    for site_block, taddr, is_tail in iter_function_invocations(project, func):
        if taddr is not None and taddr in project.kb.functions:
            call_targets[site_block] = (
                canonical_func_name(project.kb.functions[taddr].name),
                is_tail,
            )

    in_states: dict[int, LifecycleState] = {entry_node.addr: init_state}
    worklist = [entry_node]
    visits: dict[int, int] = {}
    emitted_keys: set[tuple[str, int, int]] = set()
    results: list[TaintPath] = []

    def _emit(
        cwe: str,
        sink_type: SinkType,
        src: Source,
        sink_addr: int,
        callee: str,
        vuln_arg: int,
        evidence_msg: str,
        conf: Confidence = Confidence.HIGH,
    ) -> None:
        key = (cwe, src.address, sink_addr)
        if key in emitted_keys:
            return
        emitted_keys.add(key)
        pfuncs = [func.name] if src.func_addr == func.addr else [src.func_name, func.name]
        results.append(TaintPath(
            source=src,
            sink=Sink(
                address=sink_addr,
                func_addr=func.addr,
                func_name=func.name,
                callee_name=callee,
                sink_type=sink_type,
                cwe=cwe,
                vulnerable_arg_index=vuln_arg,
            ),
            path_addrs=[src.address, sink_addr],
            path_funcs=pfuncs,
            confidence=conf,
            evidence=[evidence_msg],
        ))

    while worklist:
        node = worklist.pop(0)
        vcnt = visits.get(node.addr, 0)
        if vcnt >= 3:
            continue
        visits[node.addr] = vcnt + 1

        state = in_states[node.addr].copy()
        tmps: dict[int, PtrVal] = {}
        last_ins_addr = node.addr
        tested_ptr_ids: set[str] = set()

        try:
            irsb = project.factory.block(node.addr, size=node.size).vex
        except Exception:
            irsb = None

        if irsb is not None:
            for stmt in irsb.statements:
                stag = getattr(stmt, "tag", "")
                if stag == "Ist_IMark":
                    last_ins_addr = stmt.addr
                elif stag == "Ist_WrTmp":
                    val = _eval_ptr_expr(stmt.data, state, tmps, bits)
                    tmps[stmt.tmp] = val
                    # Check if Ist_WrTmp is a Iex_Load dereferencing a freed or unchecked-NULL pointer!
                    if getattr(stmt.data, "tag", "") == "Iex_Load":
                        addr_v = _eval_ptr_expr(stmt.data.addr, state, tmps, bits)
                        _check_pointer_deref(addr_v, last_ins_addr, "memory_load", state, func, _emit)
                    # Record comparisons testing a pointer against 0/NULL
                    if getattr(stmt.data, "tag", "") == "Iex_Binop" and "Cmp" in getattr(stmt.data, "op", ""):
                        c0 = _eval_ptr_expr(stmt.data.args[0], state, tmps, bits)
                        c1 = _eval_ptr_expr(stmt.data.args[1], state, tmps, bits)
                        if c0.ptr_id and c1.const_val == 0:
                            tested_ptr_ids.add(c0.ptr_id)
                        if c1.ptr_id and c0.const_val == 0:
                            tested_ptr_ids.add(c1.ptr_id)
                elif stag == "Ist_Put":
                    if stmt.offset != getattr(project.arch, "ip_offset", -1):
                        val = _eval_ptr_expr(stmt.data, state, tmps, bits)
                        state.regs[stmt.offset] = val
                        rname = project.arch.register_names.get(stmt.offset, "")
                        if val.ptr_id and rname.startswith("cc_"):
                            tested_ptr_ids.add(val.ptr_id)
                elif stag == "Ist_Store":
                    addr_v = _eval_ptr_expr(stmt.addr, state, tmps, bits)
                    data_v = _eval_ptr_expr(stmt.data, state, tmps, bits)
                    _check_pointer_deref(addr_v, last_ins_addr, "memory_store", state, func, _emit)
                    if addr_v.stack_base is not None and addr_v.stack_off is not None:
                        slot = (addr_v.stack_base, addr_v.stack_off)
                        state.stack_slots[slot] = data_v
                        bkey = f"stack:{slot[0]}:{slot[1]}"
                        if data_v.taints:
                            state.buf_arith[bkey] = (data_v.taints, data_v.arith_tainted)
                elif stag == "Ist_Exit":
                    gval = _eval_ptr_expr(stmt.guard, state, tmps, bits)
                    if gval.ptr_id:
                        tested_ptr_ids.add(gval.ptr_id)
                    # Any pointer tested in a conditional branch in this block is considered NULL-checked
                    for pid in tested_ptr_ids:
                        state.unchecked_allocs.pop(pid, None)

            jumpkind = getattr(irsb, "jumpkind", "")
            is_tailcall_site = node.addr in call_targets and call_targets[node.addr][1]
            if jumpkind == "Ijk_Call" or is_tailcall_site:
                call_addr = last_ins_addr
                cname, is_tail = call_targets.get(node.addr, ("", False))
                arg_vals = [state.regs.get(roff, PtrVal()) for roff in arg_offsets]

                # 1. Deallocator check: Double Free (CWE-415) or mark Freed
                if cname in DEALLOCATOR_FUNCTIONS:
                    f_idx = DEALLOCATOR_FUNCTIONS[cname]
                    if f_idx < len(arg_vals):
                        pval = arg_vals[f_idx]
                        if pval.ptr_id and pval.ptr_id in state.freed_ptrs:
                            first_free = state.freed_ptrs[pval.ptr_id]
                            src = Source(
                                address=first_free,
                                func_addr=func.addr,
                                func_name=func.name,
                                source_type=SourceType.FUNC_PARAM,
                                description=f"Prior free() at {hex(first_free)}",
                            )
                            _emit(
                                "CWE-415",
                                SinkType.DOUBLE_FREE,
                                src,
                                call_addr,
                                cname,
                                f_idx,
                                f"Pointer freed at {hex(first_free)} is passed to {cname}() again without reassignment",
                            )
                        elif pval.ptr_id and pval.const_val != 0:
                            state.freed_ptrs[pval.ptr_id] = call_addr
                            state.unchecked_allocs.pop(pval.ptr_id, None)
                else:
                    # 2. Non-deallocator call using a freed pointer -> CWE-416 Use-After-Free!
                    # Or writing into an unchecked malloc pointer -> CWE-476 NULL Deref!
                    for a_idx, aval in enumerate(arg_vals):
                        if aval.ptr_id and aval.ptr_id in state.freed_ptrs:
                            first_free = state.freed_ptrs[aval.ptr_id]
                            src = Source(
                                address=first_free,
                                func_addr=func.addr,
                                func_name=func.name,
                                source_type=SourceType.FUNC_PARAM,
                                description=f"Freed pointer from free() at {hex(first_free)}",
                            )
                            _emit(
                                "CWE-416",
                                SinkType.USE_AFTER_FREE,
                                src,
                                call_addr,
                                cname or "call",
                                a_idx,
                                f"Pointer freed at {hex(first_free)} passed as arg {a_idx} to {cname or 'callee'}()",
                            )
                        if (
                            a_idx == 0
                            and cname in ("memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat", "sprintf", "snprintf", "fgets")
                            and aval.ptr_id in state.unchecked_allocs
                        ):
                            alloc_site = state.unchecked_allocs[aval.ptr_id]
                            src = Source(
                                address=alloc_site,
                                func_addr=func.addr,
                                func_name=func.name,
                                source_type=SourceType.FUNC_PARAM,
                                description=f"Unchecked allocation return at {hex(alloc_site)}",
                            )
                            _emit(
                                "CWE-476",
                                SinkType.NULL_DEREF,
                                src,
                                call_addr,
                                cname,
                                0,
                                f"Allocator return from {hex(alloc_site)} passed to {cname}() without NULL check",
                            )

                # 3. Integer Overflow (CWE-190) into allocation or copy size arguments
                size_check_targets: tuple[int, ...] = ()
                if cname in ALLOCATOR_FUNCTIONS:
                    size_check_targets = ALLOCATOR_FUNCTIONS[cname][1]
                elif cname in ("memcpy", "memmove", "strncpy", "read", "recv", "recvfrom"):
                    size_check_targets = (2,)

                for s_idx in size_check_targets:
                    if s_idx < len(arg_vals):
                        sval = arg_vals[s_idx]
                        if sval.arith_tainted and sval.taints:
                            for origin in sorted(sval.taints):
                                src_obj = source_by_addr.get(origin) or Source(
                                    address=origin,
                                    func_addr=func.addr,
                                    func_name=func.name,
                                    source_type=SourceType.READ,
                                    description=f"Input at {hex(origin)}",
                                )
                                _emit(
                                    "CWE-190",
                                    SinkType.INTEGER_OVERFLOW,
                                    src_obj,
                                    call_addr,
                                    cname,
                                    s_idx,
                                    f"Tainted value undergoes unchecked arithmetic before sizing {cname}() arg {s_idx}",
                                )

                # 4. Constant Stack Frame Smash (CWE-120): e.g. `char buf[32]; fgets(buf, 128, stdin);`
                if cname in ("fgets", "read", "recv", "recvfrom", "memcpy", "memmove"):
                    buf_idx = 0 if cname in ("fgets", "memcpy", "memmove") else 1
                    len_idx = 1 if cname == "fgets" else 2
                    if buf_idx < len(arg_vals) and len_idx < len(arg_vals):
                        bval = arg_vals[buf_idx]
                        lval = arg_vals[len_idx]
                        if (
                            bval.stack_base == "sp"
                            and bval.stack_off is not None
                            and bval.stack_off < -8
                            and lval.const_val is not None
                        ):
                            # Distance from buffer start to saved rbp/ret at entry sp (-8 / 0)
                            dist_to_saved_frame = abs(bval.stack_off) - project.arch.bytes
                            if dist_to_saved_frame > 0 and lval.const_val > dist_to_saved_frame:
                                src_obj = Source(
                                    address=call_addr,
                                    func_addr=func.addr,
                                    func_name=func.name,
                                    source_type=reg.sources[cname].source_type if cname in reg.sources else SourceType.READ,
                                    description=f"Oversized write in {cname}()",
                                )
                                _emit(
                                    "CWE-120",
                                    SinkType.BUFFER_OVERFLOW,
                                    src_obj,
                                    call_addr,
                                    cname,
                                    len_idx,
                                    f"Constant size {lval.const_val} exceeds stack buffer distance to frame/return ({dist_to_saved_frame} bytes)",
                                )

                # 5. Update return value for Sources, Propagators (`atoi`/`strtol`), and Allocators
                matched_srcs = source_by_call_addr.get(call_addr) or source_by_call_addr.get(node.addr, [])
                ret_taints: set[int] = set()
                for ms in matched_srcs:
                    origin = frozenset({ms.address})
                    spec = reg.sources.get(cname)
                    if spec is None or spec.taints_return:
                        ret_taints.update(origin)
                    out_args = spec.tainted_out_args if spec is not None else (0, 1)
                    for o_idx in out_args:
                        if o_idx < len(arg_vals):
                            av = arg_vals[o_idx]
                            if av.stack_base is not None and av.stack_off is not None:
                                bkey = f"stack:{av.stack_base}:{av.stack_off}"
                                cur_t, cur_ar = state.buf_arith.get(bkey, (frozenset(), False))
                                state.buf_arith[bkey] = (cur_t | origin, cur_ar)

                if cname in ("atoi", "atol", "atoll", "strtol", "strtoul", "ntohl", "ntohs") and arg_vals:
                    av0 = arg_vals[0]
                    t0 = set(av0.taints)
                    if av0.stack_base is not None and av0.stack_off is not None:
                        bkey = f"stack:{av0.stack_base}:{av0.stack_off}"
                        t0.update(state.buf_arith.get(bkey, (frozenset(), False))[0])
                    ret_taints.update(t0)

                if ret_offset is not None:
                    if cname in ALLOCATOR_FUNCTIONS:
                        pid = f"heap:{hex(call_addr)}"
                        state.unchecked_allocs[pid] = call_addr
                        state.freed_ptrs.pop(pid, None)
                        state.regs[ret_offset] = PtrVal(
                            ptr_id=pid,
                            alloc_addr=call_addr,
                            taints=frozenset(ret_taints),
                        )
                    elif ret_taints:
                        state.regs[ret_offset] = PtrVal(taints=frozenset(ret_taints))
                    else:
                        state.regs[ret_offset] = PtrVal()

                if not is_tail and sp_offset is not None and getattr(project.arch, "call_pushes_ret", False):
                    sp_v = state.regs.get(sp_offset)
                    if sp_v is not None and sp_v.stack_base is not None and sp_v.stack_off is not None:
                        state.regs[sp_offset] = PtrVal(
                            stack_base=sp_v.stack_base,
                            stack_off=sp_v.stack_off + project.arch.bytes,
                        )

        for succ in func_graph.successors(node):
            succ_state = in_states.get(succ.addr)
            if succ_state is None:
                in_states[succ.addr] = state.copy()
                worklist.append(succ)
            elif succ_state.merge_from(state):
                worklist.append(succ)

    return results


def _check_pointer_deref(
    addr_v: PtrVal,
    ins_addr: int,
    op_label: str,
    state: LifecycleState,
    func,
    emit_fn,
) -> None:
    if not addr_v.ptr_id:
        return
    if addr_v.ptr_id in state.freed_ptrs:
        free_site = state.freed_ptrs[addr_v.ptr_id]
        src = Source(
            address=free_site,
            func_addr=func.addr,
            func_name=func.name,
            source_type=SourceType.FUNC_PARAM,
            description=f"Freed pointer from free() at {hex(free_site)}",
        )
        emit_fn(
            "CWE-416",
            SinkType.USE_AFTER_FREE,
            src,
            ins_addr,
            op_label,
            0,
            f"Direct {op_label} on pointer freed at {hex(free_site)}",
        )
    elif addr_v.ptr_id in state.unchecked_allocs:
        alloc_site = state.unchecked_allocs[addr_v.ptr_id]
        src = Source(
            address=alloc_site,
            func_addr=func.addr,
            func_name=func.name,
            source_type=SourceType.FUNC_PARAM,
            description=f"Unchecked allocation at {hex(alloc_site)}",
        )
        emit_fn(
            "CWE-476",
            SinkType.NULL_DEREF,
            src,
            ins_addr,
            op_label,
            0,
            f"Direct {op_label} on allocator return from {hex(alloc_site)} before NULL check",
        )
