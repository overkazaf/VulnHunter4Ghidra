package vulnhunter4ghidra.actions;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import vulnhunter4ghidra.VulnHunter4GhidraPlugin;
import vulnhunter4ghidra.engine.EngineProtocol;
import vulnhunter4ghidra.engine.EngineProtocol.Response;

public class ScanVulnsAction extends DockingAction {

	private final VulnHunter4GhidraPlugin plugin;
	private static final Gson GSON = new Gson();

	public ScanVulnsAction(VulnHunter4GhidraPlugin plugin) {
		super("Scan for Vulnerabilities", plugin.getName());
		this.plugin = plugin;
		setMenuBarData(new MenuData(
			new String[] { "VulnHunter4Ghidra", "Scan Functions" }, null, "VulnHunter"));
		plugin.getTool().addAction(this);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		plugin.ensureEngineStarted();
		if (!plugin.getEngineManager().isRunning()) {
			return;
		}

		ProgramManager pm = plugin.getTool().getService(ProgramManager.class);
		if (pm == null) return;
		Program program = pm.getCurrentProgram();
		if (program == null) return;

		FunctionManager fm = program.getFunctionManager();
		FunctionIterator functions = fm.getFunctions(true);

		JsonArray funcArray = new JsonArray();
		while (functions.hasNext()) {
			Function func = functions.next();
			if (func.isExternal() || func.isThunk()) {
				continue;
			}
			JsonObject funcObj = new JsonObject();
			funcObj.addProperty("func_addr", "0x" + Long.toHexString(func.getEntryPoint().getOffset()));
			funcObj.addProperty("func_name", func.getName());
			funcObj.addProperty("is_exported",
				program.getSymbolTable().isExternalEntryPoint(func.getEntryPoint()));

			JsonArray callsites = new JsonArray();
			InstructionIterator instructions = program.getListing().getInstructions(func.getBody(), true);
			while (instructions.hasNext()) {
				var instr = instructions.next();
				if (instr.getFlowType().isCall()) {
					var refs = instr.getReferencesFrom();
					for (var ref : refs) {
						if (ref.getReferenceType().isCall()) {
							Function callee = fm.getFunctionAt(ref.getToAddress());
							if (callee != null) {
								JsonObject cs = new JsonObject();
								cs.addProperty("address", instr.getAddress().getOffset());
								cs.addProperty("callee_name", callee.getName());
								callsites.add(cs);
							}
						}
					}
				}
			}
			funcObj.add("callsites", callsites);

			JsonArray params = new JsonArray();
			for (int i = 0; i < func.getParameterCount(); i++) {
				var p = func.getParameter(i);
				JsonObject paramObj = new JsonObject();
				paramObj.addProperty("index", i);
				paramObj.addProperty("name", p.getName());
				paramObj.addProperty("type", p.getDataType().getDisplayName());
				paramObj.addProperty("size", p.getLength());
				params.add(paramObj);
			}
			funcObj.add("params", params);
			funcArray.add(funcObj);
		}

		try {
			Response resp = plugin.getEngineManager().sendCommandWithProgress(
				EngineProtocol.scanFunctionsCmd(GSON.toJson(funcArray)),
				progress -> {
					if (progress.getData() != null) {
						Msg.info(this, String.format("Scanning: %d/%d functions",
							progress.getDataLong("scanned", 0),
							progress.getDataLong("total", 0)));
					}
				});
			if (resp.isOk()) {
				Msg.showInfo(this, null, "VulnHunter4Ghidra",
					"Scan complete. Use 'Analyze Taint' to find vulnerability paths.");
			} else {
				Msg.showError(this, null, "VulnHunter4Ghidra",
					"Scan failed: " + resp.getMessage());
			}
		}
		catch (Exception e) {
			Msg.showError(this, null, "VulnHunter4Ghidra",
				"Error during scan: " + e.getMessage(), e);
		}
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return true;
	}
}
