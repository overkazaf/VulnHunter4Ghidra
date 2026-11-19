package vulnhunter4ghidra.ui;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.listing.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Extracts Ghidra function metadata (callsites, resolved thunks, parameter types,
 * export flags) on background worker threads with cooperative {@link TaskMonitor} support.
 */
public final class ProgramScanner {

	private ProgramScanner() {}

	public static JsonArray extractAllFunctions(Program program, TaskMonitor monitor)
			throws CancelledException {
		FunctionManager fm = program.getFunctionManager();
		int total = fm.getFunctionCount();
		if (monitor != null) {
			monitor.initialize(total);
			monitor.setMessage("Extracting function metadata from Ghidra...");
		}

		JsonArray funcArray = new JsonArray();
		FunctionIterator functions = fm.getFunctions(true);
		int count = 0;
		while (functions.hasNext()) {
			if (monitor != null) {
				monitor.checkCancelled();
				monitor.setProgress(++count);
			}
			Function func = functions.next();
			if (func.isExternal() || func.isThunk()) {
				continue;
			}
			funcArray.add(extractSingleFunction(program, func));
		}
		return funcArray;
	}

	public static JsonObject extractSingleFunction(Program program, Function func) {
		FunctionManager fm = program.getFunctionManager();
		JsonObject funcObj = new JsonObject();
		funcObj.addProperty("func_addr", "0x" + Long.toHexString(func.getEntryPoint().getOffset()));
		funcObj.addProperty("func_name", func.getName());
		funcObj.addProperty("is_exported",
			program.getSymbolTable().isExternalEntryPoint(func.getEntryPoint()));

		JsonArray callsites = new JsonArray();
		InstructionIterator instructions = program.getListing().getInstructions(func.getBody(), true);
		while (instructions.hasNext()) {
			Instruction instr = instructions.next();
			if (instr.getFlowType().isCall()) {
				for (var ref : instr.getReferencesFrom()) {
					if (ref.getReferenceType().isCall()) {
						Function callee = fm.getFunctionAt(ref.getToAddress());
						if (callee != null) {
							Function resolved = callee.isThunk()
								? callee.getThunkedFunction(true)
								: callee;
							String calleeName = resolved != null ? resolved.getName() : callee.getName();
							JsonObject cs = new JsonObject();
							cs.addProperty("address", instr.getAddress().getOffset());
							cs.addProperty("callee_name", calleeName);
							callsites.add(cs);
						}
					}
				}
			}
		}
		funcObj.add("callsites", callsites);

		JsonArray params = new JsonArray();
		for (int i = 0; i < func.getParameterCount(); i++) {
			Parameter p = func.getParameter(i);
			JsonObject paramObj = new JsonObject();
			paramObj.addProperty("index", i);
			paramObj.addProperty("name", p.getName());
			paramObj.addProperty("type", p.getDataType().getDisplayName());
			paramObj.addProperty("size", p.getLength());
			params.add(paramObj);
		}
		funcObj.add("params", params);
		return funcObj;
	}
}
