package vulnhunter4ghidra.pcode;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Native Ghidra Decompiler High P-Code SSA taint & pointer lifecycle analyzer.
 * <p>
 * Operates directly on Ghidra's {@link HighFunction} SSA {@link Varnode} def-use chains,
 * providing architecture-independent analysis across all 20+ Ghidra SLEIGH processors
 * (including raw firmware dumps and remote projects without a local binary file) and
 * fusing seamlessly with Python angr VEX/Z3 results in Hybrid mode.
 */
public class PCodeTaintAnalyzer {

	private record SourceSeed(
		long address,
		long funcAddr,
		String funcName,
		String sourceType,
		String description,
		Integer paramIndex,
		boolean arithModified
	) {
		SourceSeed withArith() {
			return new SourceSeed(address, funcAddr, funcName, sourceType, description, paramIndex, true);
		}
	}

	private record SinkRule(
		String sinkType,
		String cwe,
		String severity,
		int vulnArgIdx,
		int[] taintedArgIndices,
		Integer nonConstArgIdx
	) {}

	private static final Map<String, String> SOURCE_CALLEES = Map.ofEntries(
		Map.entry("recv", "recv"),
		Map.entry("recvfrom", "recv"),
		Map.entry("recvmsg", "recv"),
		Map.entry("read", "read"),
		Map.entry("pread", "read"),
		Map.entry("fread", "file_read"),
		Map.entry("fgets", "fgets"),
		Map.entry("gets", "fgets"),
		Map.entry("getline", "stdin"),
		Map.entry("scanf", "scanf"),
		Map.entry("sscanf", "scanf"),
		Map.entry("fscanf", "scanf"),
		Map.entry("getenv", "env"),
		Map.entry("secure_getenv", "env")
	);

	private static final Map<String, int[]> SOURCE_OUT_ARGS = Map.ofEntries(
		Map.entry("recv", new int[] { 1 }),
		Map.entry("recvfrom", new int[] { 1 }),
		Map.entry("read", new int[] { 1 }),
		Map.entry("pread", new int[] { 1 }),
		Map.entry("fread", new int[] { 0 }),
		Map.entry("fgets", new int[] { 0 }),
		Map.entry("gets", new int[] { 0 }),
		Map.entry("getline", new int[] { 0 }),
		Map.entry("scanf", new int[] { 1, 2 }),
		Map.entry("sscanf", new int[] { 2 }),
		Map.entry("fscanf", new int[] { 2 })
	);

	private static final Map<String, SinkRule> SINK_RULES = Map.ofEntries(
		Map.entry("memcpy", new SinkRule("buffer_overflow", "CWE-120", "critical", 0, new int[] { 1, 2 }, null)),
		Map.entry("memmove", new SinkRule("buffer_overflow", "CWE-120", "critical", 0, new int[] { 1, 2 }, null)),
		Map.entry("strcpy", new SinkRule("buffer_overflow", "CWE-120", "critical", 0, new int[] { 1 }, 1)),
		Map.entry("strncpy", new SinkRule("buffer_overflow", "CWE-120", "critical", 0, new int[] { 1, 2 }, null)),
		Map.entry("strcat", new SinkRule("buffer_overflow", "CWE-120", "critical", 0, new int[] { 1 }, 1)),
		Map.entry("strncat", new SinkRule("buffer_overflow", "CWE-120", "critical", 0, new int[] { 1, 2 }, null)),
		Map.entry("gets", new SinkRule("buffer_overflow", "CWE-120", "critical", 0, new int[] { 0 }, null)),
		Map.entry("printf", new SinkRule("format_string", "CWE-134", "critical", 0, new int[] { 0 }, 0)),
		Map.entry("vprintf", new SinkRule("format_string", "CWE-134", "critical", 0, new int[] { 0 }, 0)),
		Map.entry("sprintf", new SinkRule("format_string", "CWE-134", "critical", 1, new int[] { 1 }, 1)),
		Map.entry("fprintf", new SinkRule("format_string", "CWE-134", "critical", 1, new int[] { 1 }, 1)),
		Map.entry("snprintf", new SinkRule("format_string", "CWE-134", "critical", 2, new int[] { 2 }, 2)),
		Map.entry("vsnprintf", new SinkRule("format_string", "CWE-134", "critical", 2, new int[] { 2 }, 2)),
		Map.entry("syslog", new SinkRule("format_string", "CWE-134", "critical", 1, new int[] { 1 }, 1)),
		Map.entry("system", new SinkRule("command_injection", "CWE-78", "critical", 0, new int[] { 0 }, 0)),
		Map.entry("popen", new SinkRule("command_injection", "CWE-78", "critical", 0, new int[] { 0 }, 0)),
		Map.entry("execve", new SinkRule("command_injection", "CWE-78", "critical", 0, new int[] { 0, 1 }, 0)),
		Map.entry("execvp", new SinkRule("command_injection", "CWE-78", "critical", 0, new int[] { 0, 1 }, 0))
	);

	private static final Set<String> PROPAGATOR_CALLEES = Set.of(
		"atoi", "atol", "atoll", "strtol", "strtoul", "strdup", "strndup",
		"strchr", "strstr", "strcpy", "strncpy", "strcat", "memcpy", "memmove",
		"sprintf", "snprintf"
	);

	private static final Set<String> ALLOCATOR_CALLEES = Set.of(
		"malloc", "calloc", "realloc"
	);

	private static final Set<String> DEALLOCATOR_CALLEES = Set.of(
		"free", "cfree"
	);

	public JsonArray analyzeProgram(Program program, Function singleTarget, TaskMonitor monitor)
			throws CancelledException {
		JsonArray findings = new JsonArray();
		if (program == null) {
			return findings;
		}

		DecompInterface ifc = new DecompInterface();
		ifc.setOptions(new DecompileOptions());
		ifc.toggleCCode(false);
		ifc.toggleSyntaxTree(true);
		if (!ifc.openProgram(program)) {
			return findings;
		}

		try {
			List<Function> targets = new ArrayList<>();
			if (singleTarget != null) {
				targets.add(singleTarget);
			}
			else {
				FunctionIterator iter = program.getFunctionManager().getFunctions(true);
				while (iter.hasNext()) {
					Function fn = iter.next();
					if (!fn.isExternal() && !fn.isThunk()) {
						targets.add(fn);
					}
				}
			}

			if (monitor != null) {
				monitor.initialize(targets.size());
				monitor.setMessage("Running Ghidra High P-Code SSA taint analysis...");
			}

			int idx = 0;
			int findingSeq = 0;
			for (Function fn : targets) {
				if (monitor != null) {
					monitor.checkCancelled();
					monitor.setProgress(++idx);
				}
				DecompileResults res = ifc.decompileFunction(fn, 15, monitor);
				if (res == null || !res.decompileCompleted()) {
					continue;
				}
				HighFunction hf = res.getHighFunction();
				if (hf == null) {
					continue;
				}
				List<JsonObject> fnFindings = analyzeHighFunction(program, fn, hf);
				for (JsonObject f : fnFindings) {
					f.addProperty("finding_id", ++findingSeq);
					findings.add(f);
				}
			}
		}
		finally {
			ifc.dispose();
		}
		return findings;
	}

	private List<JsonObject> analyzeHighFunction(Program program, Function fn, HighFunction hf) {
		List<JsonObject> results = new ArrayList<>();
		long funcAddr = fn.getEntryPoint().getOffset();
		String funcName = fn.getName();
		String canonFunc = normalizeSymbol(funcName);
		boolean isExported = program.getSymbolTable().isExternalEntryPoint(fn.getEntryPoint());

		Map<Varnode, SourceSeed> tainted = new IdentityHashMap<>();
		Map<Long, SourceSeed> taintedStackOffsets = new HashMap<>();
		Deque<Varnode> worklist = new ArrayDeque<>();

		// 1. Seed parameters (argv in main, or buffer/pointer parameters on exported APIs)
		LocalSymbolMap symMap = hf.getLocalSymbolMap();
		Iterator<HighSymbol> symbols = symMap.getSymbols();
		while (symbols.hasNext()) {
			HighSymbol sym = symbols.next();
			if (!sym.isParameter()) {
				continue;
			}
			int slot = sym.getCategoryIndex();
			String typeName = sym.getDataType() != null ? sym.getDataType().getDisplayName() : "";
			SourceSeed seed = null;
			if (("main".equals(canonFunc) || "wmain".equals(canonFunc))
					&& (slot == 1 || typeName.contains("**"))) {
				seed = new SourceSeed(funcAddr, funcAddr, funcName, "argv",
					"argv from " + funcName + "()", slot, false);
			}
			else if (!"main".equals(canonFunc) && isExported && typeName.endsWith("*")) {
				seed = new SourceSeed(funcAddr, funcAddr, funcName, "func_param",
					"Parameter " + slot + ": " + sym.getName() + " (" + typeName + ")", slot, false);
			}
			if (seed != null && sym.getHighVariable() != null) {
				for (Varnode inst : sym.getHighVariable().getInstances()) {
					seedVarnode(inst, seed, tainted, worklist);
				}
			}
		}

		// 2. Collect CALL sites in order to seed Sources and check Sinks/Lifecycles
		List<PcodeOpAST> callOps = new ArrayList<>();
		Iterator<PcodeOpAST> opIter = hf.getPcodeOps();
		while (opIter.hasNext()) {
			PcodeOpAST op = opIter.next();
			if (op.getOpcode() == PcodeOp.CALL) {
				callOps.add(op);
			}
		}

		for (PcodeOpAST callOp : callOps) {
			String callee = resolveCalleeName(program, callOp);
			if (callee == null) {
				continue;
			}
			long siteAddr = callOp.getSeqnum().getTarget().getOffset();
			String srcType = SOURCE_CALLEES.get(callee);
			if (srcType != null) {
				SourceSeed seed = new SourceSeed(
					siteAddr, funcAddr, funcName, srcType, "Call to " + callee + "()", null, false);
				if (callOp.getOutput() != null) {
					seedVarnode(callOp.getOutput(), seed, tainted, worklist);
				}
				int[] outArgs = SOURCE_OUT_ARGS.getOrDefault(callee, new int[0]);
				for (int argIdx : outArgs) {
					if (1 + argIdx < callOp.getNumInputs()) {
						Varnode bufVn = callOp.getInput(1 + argIdx);
						seedVarnode(bufVn, seed, tainted, worklist);
						Long stackOff = resolveStackOffset(bufVn);
						if (stackOff != null) {
							taintedStackOffsets.put(stackOff, seed);
						}
					}
				}
			}
		}

		// Also seed any PTRSUB referencing a tainted local stack buffer
		Iterator<PcodeOpAST> allOps = hf.getPcodeOps();
		while (allOps.hasNext()) {
			PcodeOpAST op = allOps.next();
			if (op.getOpcode() == PcodeOp.PTRSUB && op.getOutput() != null) {
				Long soff = resolveStackOffset(op.getOutput());
				if (soff != null && taintedStackOffsets.containsKey(soff)) {
					seedVarnode(op.getOutput(), taintedStackOffsets.get(soff), tainted, worklist);
				}
			}
		}

		// 3. Forward SSA Def-Use worklist propagation
		while (!worklist.isEmpty()) {
			Varnode cur = worklist.poll();
			SourceSeed curSeed = tainted.get(cur);
			if (curSeed == null) {
				continue;
			}

			Iterator<PcodeOp> uses = cur.getDescendants();
			while (uses.hasNext()) {
				PcodeOp use = uses.next();
				int opc = use.getOpcode();
				switch (opc) {
					case PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT,
						 PcodeOp.SUBPIECE, PcodeOp.MULTIEQUAL, PcodeOp.INDIRECT,
						 PcodeOp.PTRADD, PcodeOp.PTRSUB, PcodeOp.LOAD -> {
						if (use.getOutput() != null) {
							seedVarnode(use.getOutput(), curSeed, tainted, worklist);
						}
					}
					case PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.INT_MULT, PcodeOp.INT_LEFT -> {
						if (use.getOutput() != null) {
							seedVarnode(use.getOutput(), curSeed.withArith(), tainted, worklist);
						}
					}
					case PcodeOp.CALL -> {
						String callee = resolveCalleeName(program, use);
						if (callee != null && PROPAGATOR_CALLEES.contains(callee)) {
							if (use.getOutput() != null) {
								seedVarnode(use.getOutput(), curSeed, tainted, worklist);
							}
							if (use.getNumInputs() > 1) {
								Varnode dst = use.getInput(1);
								seedVarnode(dst, curSeed, tainted, worklist);
								Long soff = resolveStackOffset(dst);
								if (soff != null) {
									taintedStackOffsets.put(soff, curSeed);
								}
							}
						}
					}
					default -> {}
				}
			}
		}

		Set<String> dedup = new HashSet<>();

		// 4. Evaluate Sinks, Integer Overflow (CWE-190), and SSA Double-Free/UAF
		for (int i = 0; i < callOps.size(); i++) {
			PcodeOpAST callOp = callOps.get(i);
			String callee = resolveCalleeName(program, callOp);
			if (callee == null) {
				continue;
			}
			long sinkAddr = callOp.getSeqnum().getTarget().getOffset();

			// 4a. Taint Sinks (CWE-120, CWE-134, CWE-78)
			SinkRule rule = SINK_RULES.get(callee);
			if (rule != null) {
				if (rule.nonConstArgIdx() != null && 1 + rule.nonConstArgIdx() < callOp.getNumInputs()) {
					Varnode reqVn = callOp.getInput(1 + rule.nonConstArgIdx());
					if (isReadOnlyConstantString(program, reqVn)) {
						rule = null;
					}
				}
			}
			if (rule != null) {
				for (int argIdx : rule.taintedArgIndices()) {
					if (1 + argIdx < callOp.getNumInputs()) {
						Varnode argVn = callOp.getInput(1 + argIdx);
						SourceSeed hit = lookupTaint(argVn, tainted, taintedStackOffsets);
						if (hit != null && hit.address() != sinkAddr) {
							String key = rule.cwe() + ":" + sinkAddr;
							if (dedup.add(key)) {
								results.add(buildFindingJson(
									rule.cwe(), rule.severity(), rule.sinkType(), callee,
									rule.vulnArgIdx(), funcAddr, funcName, sinkAddr, hit,
									"Ghidra High P-Code SSA def-use chain confirmed taint in arg " + argIdx));
							}
							break;
						}
					}
				}
			}

			// 4b. CWE-190 Integer Overflow into Allocator size
			if (ALLOCATOR_CALLEES.contains(callee) && callOp.getNumInputs() > 1) {
				int sizeIdx = "realloc".equals(callee) ? 1 : 0;
				if (1 + sizeIdx < callOp.getNumInputs()) {
					SourceSeed hit = lookupTaint(callOp.getInput(1 + sizeIdx), tainted, taintedStackOffsets);
					if (hit != null && hit.arithModified()) {
						String key = "CWE-190:" + sinkAddr;
						if (dedup.add(key)) {
							results.add(buildFindingJson(
								"CWE-190", "high", "integer_overflow", callee,
								sizeIdx, funcAddr, funcName, sinkAddr, hit,
								"Ghidra High P-Code SSA detected arithmetic on tainted value sizing " + callee + "()"));
						}
					}
				}
			}

			// 4c. SSA Pointer Lifecycle: CWE-415 Double Free & CWE-416 Use-After-Free
			if (DEALLOCATOR_CALLEES.contains(callee) && callOp.getNumInputs() > 1) {
				Varnode freedVn = unwrapCastCopy(callOp.getInput(1));
				if (freedVn != null && !freedVn.isConstant()) {
					SourceSeed freeOrigin = new SourceSeed(
						sinkAddr, funcAddr, funcName, "func_param",
						"Freed pointer from " + callee + "() at 0x" + Long.toHexString(sinkAddr),
						null, false);
					// Check subsequent CALL ops in the same basic block or reachable blocks using the same SSA Varnode
					for (int j = i + 1; j < callOps.size(); j++) {
						PcodeOpAST laterCall = callOps.get(j);
						long laterAddr = laterCall.getSeqnum().getTarget().getOffset();
						if (laterAddr <= sinkAddr) {
							continue;
						}
						String laterCallee = resolveCalleeName(program, laterCall);
						for (int k = 1; k < laterCall.getNumInputs(); k++) {
							Varnode laterArg = unwrapCastCopy(laterCall.getInput(k));
							if (sameSsaValue(freedVn, laterArg)) {
								if (laterCallee != null && DEALLOCATOR_CALLEES.contains(laterCallee)) {
									String key = "CWE-415:" + laterAddr;
									if (dedup.add(key)) {
										results.add(buildFindingJson(
											"CWE-415", "critical", "double_free", laterCallee,
											k - 1, funcAddr, funcName, laterAddr, freeOrigin,
											"Ghidra High P-Code SSA: identical SSA Varnode passed to " + laterCallee + "() twice"));
									}
								}
								else {
									String key = "CWE-416:" + laterAddr;
									if (dedup.add(key)) {
										results.add(buildFindingJson(
											"CWE-416", "critical", "use_after_free",
											laterCallee != null ? laterCallee : "call",
											k - 1, funcAddr, funcName, laterAddr, freeOrigin,
											"Ghidra High P-Code SSA: freed SSA Varnode reused in " + (laterCallee != null ? laterCallee : "call") + "()"));
									}
								}
							}
						}
					}
				}
			}
		}

		return results;
	}

	private static void seedVarnode(
			Varnode vn, SourceSeed seed,
			Map<Varnode, SourceSeed> tainted, Deque<Varnode> worklist) {
		if (vn == null || vn.isConstant()) {
			return;
		}
		SourceSeed prev = tainted.get(vn);
		if (prev == null || (!prev.arithModified() && seed.arithModified())) {
			tainted.put(vn, seed);
			worklist.add(vn);
		}
	}

	private static SourceSeed lookupTaint(
			Varnode vn, Map<Varnode, SourceSeed> tainted, Map<Long, SourceSeed> stackTaints) {
		if (vn == null) {
			return null;
		}
		SourceSeed direct = tainted.get(vn);
		if (direct != null) {
			return direct;
		}
		Long soff = resolveStackOffset(vn);
		if (soff != null) {
			return stackTaints.get(soff);
		}
		return null;
	}

	private static Varnode unwrapCastCopy(Varnode vn) {
		int depth = 0;
		while (vn != null && depth++ < 6) {
			PcodeOp def = vn.getDef();
			if (def == null) {
				break;
			}
			int opc = def.getOpcode();
			if ((opc == PcodeOp.CAST || opc == PcodeOp.COPY) && def.getNumInputs() >= 1) {
				vn = def.getInput(0);
			}
			else {
				break;
			}
		}
		return vn;
	}

	private static boolean sameSsaValue(Varnode a, Varnode b) {
		if (a == null || b == null) {
			return false;
		}
		if (a == b) {
			return true;
		}
		return a.getHigh() != null && a.getHigh() == b.getHigh();
	}

	private static Long resolveStackOffset(Varnode vn) {
		Varnode cur = unwrapCastCopy(vn);
		if (cur == null) {
			return null;
		}
		PcodeOp def = cur.getDef();
		if (def != null && def.getOpcode() == PcodeOp.PTRSUB && def.getNumInputs() >= 2) {
			Varnode base = def.getInput(0);
			Varnode off = def.getInput(1);
			if (base != null && base.isRegister() && off != null && off.isConstant()) {
				return off.getOffset();
			}
		}
		return null;
	}

	private static boolean isReadOnlyConstantString(Program program, Varnode vn) {
		Varnode cur = unwrapCastCopy(vn);
		if (cur == null) {
			return false;
		}
		Long rawAddr = null;
		if (cur.isConstant()) {
			rawAddr = cur.getOffset();
		}
		else {
			PcodeOp def = cur.getDef();
			if (def != null && (def.getOpcode() == PcodeOp.PTRSUB || def.getOpcode() == PcodeOp.COPY)) {
				Varnode lastIn = def.getInput(def.getNumInputs() - 1);
				if (lastIn != null && lastIn.isConstant()) {
					rawAddr = lastIn.getOffset();
				}
			}
		}
		if (rawAddr == null) {
			return false;
		}
		Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(rawAddr);
		MemoryBlock block = program.getMemory().getBlock(addr);
		return block != null && !block.isWrite();
	}

	private static String resolveCalleeName(Program program, PcodeOp callOp) {
		if (callOp.getNumInputs() < 1) {
			return null;
		}
		Varnode target = callOp.getInput(0);
		if (target == null || target.getAddress() == null) {
			return null;
		}
		Function callee = program.getFunctionManager().getFunctionAt(target.getAddress());
		if (callee == null) {
			return null;
		}
		if (callee.isThunk()) {
			Function thunked = callee.getThunkedFunction(true);
			if (thunked != null) {
				callee = thunked;
			}
		}
		return normalizeSymbol(callee.getName());
	}

	public static String normalizeSymbol(String raw) {
		if (raw == null || raw.isEmpty()) {
			return "";
		}
		String s = raw.trim();
		if (s.contains("::")) {
			s = s.substring(s.lastIndexOf("::") + 2);
		}
		for (String pfx : new String[] { "sym.imp.", "imp.", "plt.", "__imp_", "_imp__" }) {
			if (s.startsWith(pfx)) {
				s = s.substring(pfx.length());
				break;
			}
		}
		if (s.contains("@")) {
			s = s.substring(0, s.indexOf('@'));
		}
		for (String iso : new String[] { "__isoc99_", "__isoc23_", "___isoc99_" }) {
			if (s.startsWith(iso)) {
				s = s.substring(iso.length());
				break;
			}
		}
		while (s.startsWith("_")) {
			s = s.substring(1);
		}
		if (s.endsWith("_chk") && s.length() > 4) {
			s = s.substring(0, s.length() - 4);
		}
		return s;
	}

	private static JsonObject buildFindingJson(
			String cwe, String severity, String sinkType, String callee,
			int vulnArgIdx, long funcAddr, String funcName, long sinkAddr,
			SourceSeed src, String evidenceText) {
		String funcHex = "0x" + Long.toHexString(funcAddr);
		String srcHex = "0x" + Long.toHexString(src.address());
		String snkHex = "0x" + Long.toHexString(sinkAddr);

		JsonObject srcObj = new JsonObject();
		srcObj.addProperty("address", srcHex);
		srcObj.addProperty("func_addr", "0x" + Long.toHexString(src.funcAddr()));
		srcObj.addProperty("func_name", src.funcName());
		srcObj.addProperty("source_type", src.sourceType());
		srcObj.addProperty("description", src.description());
		if (src.paramIndex() != null) {
			srcObj.addProperty("param_index", src.paramIndex());
		}

		JsonObject snkObj = new JsonObject();
		snkObj.addProperty("address", snkHex);
		snkObj.addProperty("func_addr", funcHex);
		snkObj.addProperty("func_name", funcName);
		snkObj.addProperty("callee_name", callee);
		snkObj.addProperty("sink_type", sinkType);
		snkObj.addProperty("cwe", cwe);
		snkObj.addProperty("vulnerable_arg_index", vulnArgIdx);

		JsonArray pathAddrs = new JsonArray();
		pathAddrs.add(srcHex);
		if (!srcHex.equals(snkHex)) {
			pathAddrs.add(snkHex);
		}
		JsonArray pathFuncs = new JsonArray();
		pathFuncs.add(funcName);

		JsonObject tpObj = new JsonObject();
		tpObj.add("source", srcObj);
		tpObj.add("sink", snkObj);
		tpObj.add("path_addrs", pathAddrs);
		tpObj.add("path_funcs", pathFuncs);
		tpObj.addProperty("path_length", pathAddrs.size());
		tpObj.addProperty("confidence", "high");

		JsonArray evArr = new JsonArray();
		evArr.add(evidenceText);

		JsonObject f = new JsonObject();
		f.addProperty("fingerprint", computeFingerprint(cwe, src.funcName(), src.sourceType(), funcName, callee));
		f.add("taint_path", tpObj);
		f.addProperty("cwe", cwe);
		f.addProperty("severity", severity);
		f.addProperty("confidence", "high");
		f.addProperty("title", sinkType + ": " + callee + " in " + funcName);
		f.addProperty("description", src.description() + " -> " + callee + "() at " + snkHex);
		f.addProperty("verified", false);
		f.add("evidence", evArr);
		return f;
	}

	private static String computeFingerprint(
			String cwe, String srcFunc, String srcType, String snkFunc, String callee) {
		try {
			String raw = String.join("|", cwe, srcFunc, srcType, snkFunc, callee, snkFunc);
			byte[] digest = MessageDigest.getInstance("SHA-256")
				.digest(raw.getBytes(StandardCharsets.UTF_8));
			StringBuilder sb = new StringBuilder(16);
			for (int i = 0; i < 8; i++) {
				sb.append(String.format("%02x", digest[i]));
			}
			return sb.toString();
		}
		catch (Exception e) {
			return Integer.toHexString(Objects.hash(cwe, srcFunc, snkFunc, callee));
		}
	}
}
