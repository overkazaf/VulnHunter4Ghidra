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
import vulnhunter4ghidra.pcode.PCodeTaintAnalyzer;
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
	private final PCodeTaintAnalyzer pcodeAnalyzer;
	private final VulnHunterProvider provider;
	private final Map<String, String> binaryPathOverrides = new HashMap<>();

	private String initializedProgramKey;
	private boolean fullScanCompleted;

	public VulnHunter4GhidraPlugin(PluginTool tool) {
		super(tool);
		this.engineManager = new EngineManager();
		this.highlighter = new TaintPathHighlighter(tool);
		this.pcodeAnalyzer = new PCodeTaintAnalyzer();
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
		String engineMode = provider.getSelectedEngineMode();
		boolean usePCode = !engineMode.startsWith("angr");
		boolean useAngr = !engineMode.startsWith("P-Code");

		TaskLauncher.launch(new Task("VulnHunter4Ghidra — Full Taint Analysis", true, true, false) {
			@Override
			public void run(TaskMonitor monitor) {
				try {
					JsonArray pcodeFindings = new JsonArray();
					if (usePCode) {
						provider.setStatus("Running native Ghidra High P-Code SSA analysis...");
						pcodeFindings = pcodeAnalyzer.analyzeProgram(program, null, monitor);
						monitor.checkCancelled();
					}

					JsonArray angrFindings = new JsonArray();
					long totalSources = 0;
					long totalSinks = 0;
					if (useAngr) {
						boolean angrReady = false;
						try {
							angrReady = ensureEngineReadyForProgram(program, monitor);
						}
						catch (Exception ex) {
							if (!usePCode) {
								throw ex;
							}
							Msg.warn(this, "Python angr engine unavailable, falling back to High P-Code SSA: "
								+ ex.getMessage());
						}

						if (angrReady) {
							if (!fullScanCompleted) {
								runScanStep(program, monitor);
							}
							monitor.checkCancelled();
							monitor.setIndeterminate(true);
							monitor.setMessage("Running angr VEX data-flow & CWE lifecycle analysis...");
							provider.setStatus("Analyzing VEX taint paths (depth=" + maxDepth
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
							angrFindings = data.getAsJsonArray("findings");
							totalSources = data.get("total_sources").getAsLong();
							totalSinks = data.get("total_sinks").getAsLong();
						}
					}

					JsonArray merged = mergeFindings(pcodeFindings, angrFindings);
					provider.updateFindings(merged);
					provider.setStatus(String.format(
						"Analysis complete [%s]: %d findings (P-Code=%d, angr=%d, sources=%d, sinks=%d)",
						engineMode, merged.size(), pcodeFindings.size(), angrFindings.size(),
						totalSources, totalSinks));
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
		String engineMode = provider.getSelectedEngineMode();
		boolean usePCode = !engineMode.startsWith("angr");
		boolean useAngr = !engineMode.startsWith("P-Code");

		TaskLauncher.launch(new Task("VulnHunter — Analyze " + func.getName(), true, false, false) {
			@Override
			public void run(TaskMonitor monitor) {
				try {
					monitor.setIndeterminate(true);
					JsonArray pcodeFindings = usePCode
						? pcodeAnalyzer.analyzeProgram(program, func, monitor)
						: new JsonArray();
					JsonArray angrFindings = new JsonArray();
					if (useAngr) {
						try {
							if (ensureEngineReadyForProgram(program, monitor)) {
								JsonObject funcObj = ProgramScanner.extractSingleFunction(program, func);
								engineManager.sendCommand(EngineProtocol.scanFunctionCmd(funcObj));
								Response resp = engineManager.sendCommand(
									EngineProtocol.analyzeTaintCmd(
										1, funcHex, provider.isSymbolicVerifyEnabled()));
								if (resp.isOk() && resp.getData() != null) {
									angrFindings = resp.getData().getAsJsonArray("findings");
								}
							}
						}
						catch (Exception ex) {
							if (!usePCode) {
								throw ex;
							}
							Msg.warn(this, "angr unavailable for single-function scan, using P-Code only");
						}
					}
					JsonArray merged = mergeFindings(pcodeFindings, angrFindings);
					provider.updateFindings(merged);
					provider.setStatus(String.format("Function %s: %d finding(s)",
						func.getName(), merged.size()));
				}
				catch (Exception e) {
					provider.setStatus("Function analysis failed: " + e.getMessage());
					Msg.showError(this, null, "VulnHunter4Ghidra",
						"Failed analyzing " + func.getName() + ": " + e.getMessage(), e);
				}
			}
		});
	}

	private static JsonArray mergeFindings(JsonArray pcodeFindings, JsonArray angrFindings) {
		if (pcodeFindings == null || pcodeFindings.isEmpty()) {
			return angrFindings != null ? angrFindings : new JsonArray();
		}
		if (angrFindings == null || angrFindings.isEmpty()) {
			return pcodeFindings;
		}

		Map<String, JsonObject> byKey = new java.util.LinkedHashMap<>();
		for (var el : angrFindings) {
			JsonObject f = el.getAsJsonObject().deepCopy();
			byKey.put(findingMatchKey(f), f);
		}

		for (var el : pcodeFindings) {
			JsonObject pf = el.getAsJsonObject();
			String key = findingMatchKey(pf);
			if (byKey.containsKey(key)) {
				JsonObject existing = byKey.get(key);
				existing.addProperty("confidence", "high");
				JsonArray ev = existing.has("evidence") && existing.get("evidence").isJsonArray()
					? existing.getAsJsonArray("evidence")
					: new JsonArray();
				JsonArray mergedEv = new JsonArray();
				mergedEv.add("[HYBRID] Independently confirmed by Ghidra High P-Code SSA and angr VEX");
				ev.forEach(mergedEv::add);
				if (pf.has("evidence") && pf.get("evidence").isJsonArray()) {
					pf.getAsJsonArray("evidence").forEach(mergedEv::add);
				}
				existing.add("evidence", mergedEv);
			}
			else {
				byKey.put(key, pf.deepCopy());
			}
		}

		JsonArray out = new JsonArray();
		int seq = 0;
		for (JsonObject f : byKey.values()) {
			f.addProperty("finding_id", ++seq);
			out.add(f);
		}
		return out;
	}

	private static String findingMatchKey(JsonObject f) {
		String cwe = f.has("cwe") ? f.get("cwe").getAsString() : "";
		JsonObject tp = f.getAsJsonObject("taint_path");
		JsonObject snk = tp != null ? tp.getAsJsonObject("sink") : null;
		if (snk == null) {
			return cwe + ":" + f.toString();
		}
		String addr = snk.has("address") ? snk.get("address").getAsString() : "";
		String fn = snk.has("func_name") ? PCodeTaintAnalyzer.normalizeSymbol(snk.get("func_name").getAsString()) : "";
		String callee = snk.has("callee_name") ? PCodeTaintAnalyzer.normalizeSymbol(snk.get("callee_name").getAsString()) : "";
		return cwe + "|" + fn + "|" + callee + "|" + addr;
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
