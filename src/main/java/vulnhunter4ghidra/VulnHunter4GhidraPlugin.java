package vulnhunter4ghidra;

import java.io.IOException;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import vulnhunter4ghidra.actions.*;
import vulnhunter4ghidra.engine.EngineManager;
import vulnhunter4ghidra.engine.EngineProtocol;

//@formatter:off
@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = "VulnHunter4Ghidra",
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Interactive Vulnerability Detection & Taint Analysis",
	description = "Detects vulnerabilities via source-sink taint analysis powered by angr."
)
//@formatter:on
public class VulnHunter4GhidraPlugin extends Plugin {

	private EngineManager engineManager;

	public VulnHunter4GhidraPlugin(PluginTool tool) {
		super(tool);
		engineManager = new EngineManager();
		new ScanVulnsAction(this);
		new AnalyzeTaintAction(this);
	}

	public EngineManager getEngineManager() {
		return engineManager;
	}

	public void ensureEngineStarted() {
		if (!engineManager.isRunning()) {
			try {
				engineManager.start();
			}
			catch (Exception e) {
				Msg.showError(this, null, "VulnHunter4Ghidra",
					"Failed to start engine: " + e.getMessage(), e);
				return;
			}
		}
		ensureInitialized();
	}

	public boolean ensureInitialized() {
		ProgramManager pm = tool.getService(ProgramManager.class);
		if (pm == null) return false;
		Program program = pm.getCurrentProgram();
		if (program == null) return false;

		String path = program.getExecutablePath();
		if (path == null || path.isBlank()) {
			Msg.showError(this, null, "VulnHunter4Ghidra",
				"Could not determine the file path of the current program.");
			return false;
		}

		if (!engineManager.isRunning()) {
			Msg.showError(this, null, "VulnHunter4Ghidra",
				"Engine is not running.");
			return false;
		}

		try {
			String baseAddr = "0x" + Long.toHexString(program.getImageBase().getOffset());
			EngineProtocol.Response resp = engineManager.sendCommand(
				EngineProtocol.initCmd(path, baseAddr));
			if (resp.isOk()) {
				Msg.info(this, "Initialized engine with: " + path + " @ " + baseAddr);
				return true;
			}
			Msg.showError(this, null, "VulnHunter4Ghidra",
				"Failed to load binary: " + resp.getMessage());
			return false;
		}
		catch (IOException e) {
			Msg.showError(this, null, "VulnHunter4Ghidra",
				"Lost connection to engine: " + e.getMessage());
			engineManager.stop();
			return false;
		}
	}

	@Override
	protected void dispose() {
		engineManager.dispose();
		super.dispose();
	}
}
