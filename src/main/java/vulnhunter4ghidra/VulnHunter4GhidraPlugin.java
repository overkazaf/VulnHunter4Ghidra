package vulnhunter4ghidra;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.swing.JFileChooser;
import javax.swing.SwingUtilities;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import vulnhunter4ghidra.actions.*;
import vulnhunter4ghidra.engine.EngineManager;
import vulnhunter4ghidra.engine.EngineProtocol;
import vulnhunter4ghidra.engine.EngineProtocol.Response;
import vulnhunter4ghidra.highlight.TaintPathHighlighter;
import vulnhunter4ghidra.ui.ProgramScanner;
import vulnhunter4ghidra.ui.VulnHunterProvider;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = "VulnHunter4Ghidra",
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Interactive Vulnerability Detection & Taint Analysis Workbench",
	description = "Detects CWE memory safety and injection vulnerabilities via VEX data-flow taint analysis, pointer lifecycle checks, and Z3 feasibility verification."
)
//@formatter:on
public class VulnHunter4GhidraPlugin extends Plugin {

	private final EngineManager engineManager;
	private final TaintPathHighlighter highlighter;
	private final VulnHunterProvider provider;
	private final Map<String, String> binaryPathOverrides = new HashMap<>();

	private String initializedProgramKey;
	private boolean fullScanCompleted;

	public VulnHunter4GhidraPlugin(PluginTool tool) {
		super(tool);
		this.engineManager = new EngineManager();
		this.highlighter = new TaintPathHighlighter(tool);
		this.provider = new VulnHunterProvider(this);

		new ScanVulnsAction(this);
		new AnalyzeTaintAction(this);
		new AnalyzeFunctionAction(this);
		new MarkCustomNodeAction(this, "source", "Mark as Custom Source");
		new MarkCustomNodeAction(this, "sink", "Mark as Custom Sink (CWE-120)");
		new MarkCustomNodeAction(this, "sanitizer", "Mark as Sanitizer");
	}

	public EngineManager getEngineManager() {
		return engineManager;
	}

	public TaintPathHighlighter getHighlighter() {
		return highlighter;
	}

	public VulnHunterProvider getProvider() {
		return provider;
	}

	public Program getCurrentProgram() {
		ProgramManager pm = tool.getService(ProgramManager.class);
		return pm != null ? pm.getCurrentProgram() : null;
	}

	public void clearHighlights() {
		highlighter.clearHighlights(getCurrentProgram());
		provider.setStatus("Cleared taint path highlights");
	}

	public synchronized boolean ensureEngineReadyForProgram(Program program, TaskMonitor monitor)
			throws IOException {
		if (program == null) {
			return false;
		}
		if (!engineManager.isRunning()) {
			if (monitor != null) {
				monitor.setMessage("Starting VulnHunter4Ghidra Python engine...");
			}
			engineManager.start();
			initializedProgramKey = null;
			fullScanCompleted = false;
		}

		String path = resolveBinaryPath(program);
		if (path == null) {
			return false;
		}
		String baseAddr = "0x" + Long.toHexString(program.getImageBase().getOffset());
		String key = path + "@" + baseAddr;

		if (key.equals(initializedProgramKey)) {
			return true;
		}

		if (monitor != null) {
			monitor.setMessage("Loading binary into angr engine (" + baseAddr + ")...");
		}
		Response resp = engineManager.sendCommand(EngineProtocol.initCmd(path, baseAddr));
		if (!resp.isOk()) {
			throw new IOException("Failed to initialize binary: " + resp.getMessage());
		}
		initializedProgramKey = key;
		fullScanCompleted = false;
		Msg.info(this, "Initialized engine with " + path + " @ " + baseAddr);
		return true;
	}

	private String resolveBinaryPath(Program program) {
		String progDomainPath = program.getDomainFile().getPathname();
		if (binaryPathOverrides.containsKey(progDomainPath)) {
			return binaryPathOverrides.get(progDomainPath);
		}
		String execPath = program.getExecutablePath();
		if (execPath != null && !execPath.isBlank() && new File(execPath).isFile()) {
			return execPath;
		}

		final String[] chosen = new String[1];
		try {
			SwingUtilities.invokeAndWait(() -> {
				JFileChooser chooser = new JFileChooser();
				chooser.setDialogTitle(
					"Locate local binary file for '" + program.getName() + "'");
				if (chooser.showOpenDialog(provider.getComponent()) == JFileChooser.APPROVE_OPTION) {
					chosen[0] = chooser.getSelectedFile().getAbsolutePath();
				}
			});
		}
		catch (Exception ignored) {}

		if (chosen[0] != null) {
			binaryPathOverrides.put(progDomainPath, chosen[0]);
			return chosen[0];
		}
		return null;
	}

	public void runScanOnlyTask() {
		Program program = getCurrentProgram();
		if (program == null) {
			return;
		}
		TaskLauncher.launch(new Task("VulnHunter4Ghidra — Scan Functions", true, true, false) {
			@Override
			public void run(TaskMonitor monitor) {
				try {
					if (!ensureEngineReadyForProgram(program, monitor)) {
						provider.setStatus("Scan cancelled — binary file not available");
						return;
					}
					runScanStep(program, monitor);
				}
				catch (CancelledException ce) {
					engineManager.requestCancel();
					provider.setStatus("Scan cancelled");
				}
				catch (Exception e) {
					provider.setStatus("Scan failed: " + e.getMessage());
					Msg.showError(this, null, "VulnHunter4Ghidra", "Scan failed: " + e.getMessage(), e);
				}
			}
		});
	}

	public void runFullAnalysisTask(int maxDepth, boolean verify) {
		Program program = getCurrentProgram();
		if (program == null) {
			return;
		}
		TaskLauncher.launch(new Task("VulnHunter4Ghidra — Full Taint Analysis", true, true, false) {
			@Override
			public void run(TaskMonitor monitor) {
				try {
					if (!ensureEngineReadyForProgram(program, monitor)) {
						provider.setStatus("Analysis aborted — binary file not available");
						return;
					}
					if (!fullScanCompleted) {
						runScanStep(program, monitor);
					}
					monitor.checkCancelled();
					monitor.setIndeterminate(true);
					monitor.setMessage("Running VEX data-flow taint & CWE lifecycle analysis...");
					provider.setStatus("Analyzing taint paths (depth=" + maxDepth
						+ (verify ? ", Z3=on" : "") + ")...");

					Response resp = engineManager.sendCommand(
						EngineProtocol.analyzeTaintCmd(maxDepth, null, verify));
					if (monitor.isCancelled()) {
						throw new CancelledException();
					}
					if (!resp.isOk()) {
						throw new IOException(resp.getMessage());
					}
					JsonObject data = resp.getData();
					JsonArray findings = data.getAsJsonArray("findings");
					provider.updateFindings(findings);
					provider.setStatus(String.format(
						"Analysis complete: %d findings (%d sources, %d sinks)",
						findings != null ? findings.size() : 0,
						data.get("total_sources").getAsLong(),
						data.get("total_sinks").getAsLong()));
				}
				catch (CancelledException ce) {
					engineManager.requestCancel();
					fullScanCompleted = false;
					provider.setStatus("Analysis cancelled");
				}
				catch (Exception e) {
					provider.setStatus("Analysis failed: " + e.getMessage());
					Msg.showError(this, null, "VulnHunter4Ghidra",
						"Error during taint analysis: " + e.getMessage(), e);
				}
			}
		});
	}

	public void runSingleFunctionAnalysisTask(Function func) {
		Program program = func.getProgram();
		String funcHex = "0x" + Long.toHexString(func.getEntryPoint().getOffset());
		TaskLauncher.launch(new Task("VulnHunter — Analyze " + func.getName(), true, false, false) {
			@Override
			public void run(TaskMonitor monitor) {
				try {
					monitor.setIndeterminate(true);
					if (!ensureEngineReadyForProgram(program, monitor)) {
						return;
					}
					JsonObject funcObj = ProgramScanner.extractSingleFunction(program, func);
					engineManager.sendCommand(EngineProtocol.scanFunctionCmd(funcObj));
					Response resp = engineManager.sendCommand(
						EngineProtocol.analyzeTaintCmd(1, funcHex, provider.isSymbolicVerifyEnabled()));
					if (!resp.isOk()) {
						throw new IOException(resp.getMessage());
					}
					JsonArray findings = resp.getData().getAsJsonArray("findings");
					provider.updateFindings(findings);
					provider.setStatus(String.format("Function %s: %d finding(s)",
						func.getName(), findings != null ? findings.size() : 0));
				}
				catch (Exception e) {
					provider.setStatus("Function analysis failed: " + e.getMessage());
					Msg.showError(this, null, "VulnHunter4Ghidra",
						"Failed analyzing " + func.getName() + ": " + e.getMessage(), e);
				}
			}
		});
	}

	public void markCustomNodeTask(String role, String funcName, String addrHex) {
		Program program = getCurrentProgram();
		if (program == null) {
			return;
		}
		TaskLauncher.launch(new Task("VulnHunter — Mark Custom " + role, false, false, false) {
			@Override
			public void run(TaskMonitor monitor) {
				try {
					if (!ensureEngineReadyForProgram(program, monitor)) {
						return;
					}
					Response resp = engineManager.sendCommand(
						EngineProtocol.markCustomCmd(role, funcName, addrHex,
							"CWE-120", "buffer_overflow", 0));
					if (resp.isOk()) {
						fullScanCompleted = false;
						provider.setStatus("Marked "
							+ (funcName != null ? funcName : addrHex) + " as custom " + role);
					}
				}
				catch (Exception e) {
					Msg.showError(this, null, "VulnHunter4Ghidra",
						"Failed to mark custom " + role + ": " + e.getMessage(), e);
				}
			}
		});
	}

	public void loadCustomRulesTask(String rulesPath) {
		Program program = getCurrentProgram();
		TaskLauncher.launch(new Task("VulnHunter — Load Rules", false, false, false) {
			@Override
			public void run(TaskMonitor monitor) {
				try {
					if (program != null && !ensureEngineReadyForProgram(program, monitor)) {
						return;
					}
					else if (!engineManager.isRunning()) {
						engineManager.start();
					}
					Response resp = engineManager.sendCommand(EngineProtocol.loadRulesCmd(rulesPath));
					if (!resp.isOk()) {
						throw new IOException(resp.getMessage());
					}
					fullScanCompleted = false;
					JsonObject d = resp.getData();
					provider.setStatus(String.format(
						"Loaded rules (+%d sources, +%d sinks, +%d sanitizers) — re-run Scan & Analyze",
						d.get("sources_added").getAsInt(),
						d.get("sinks_added").getAsInt(),
						d.get("sanitizers_added").getAsInt()));
				}
				catch (Exception e) {
					Msg.showError(this, null, "VulnHunter4Ghidra",
						"Failed to load rules: " + e.getMessage(), e);
				}
			}
		});
	}

	private void runScanStep(Program program, TaskMonitor monitor)
			throws CancelledException, IOException {
		JsonArray funcArray = ProgramScanner.extractAllFunctions(program, monitor);
		monitor.checkCancelled();
		monitor.initialize(funcArray.size());
		monitor.setMessage("Scanning functions in engine...");

		Response resp = engineManager.sendCommandWithProgress(
			EngineProtocol.scanFunctionsCmd(funcArray, true),
			progress -> {
				if (progress.getData() != null) {
					long scanned = progress.getDataLong("scanned", 0);
					monitor.setProgress(scanned);
					provider.setStatus("Scanning: " + scanned + "/" + funcArray.size() + " functions");
				}
			});
		if (!resp.isOk()) {
			throw new IOException("Scan failed: " + resp.getMessage());
		}

		Response srcResp = engineManager.sendCommand(EngineProtocol.getSourcesCmd());
		Response snkResp = engineManager.sendCommand(EngineProtocol.getSinksCmd());
		provider.updateInventory(
			srcResp.isOk() ? srcResp.getDataArray("sources") : null,
			snkResp.isOk() ? snkResp.getDataArray("sinks") : null);
		fullScanCompleted = true;
		provider.setStatus(String.format("Scanned %d functions (%d sources, %d sinks)",
			funcArray.size(),
			resp.getDataLong("total_sources", 0),
			resp.getDataLong("total_sinks", 0)));
	}

	@Override
	protected void dispose() {
		highlighter.clearHighlights(getCurrentProgram());
		provider.closeComponent();
		engineManager.dispose();
		super.dispose();
	}
}
