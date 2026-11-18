package vulnhunter4ghidra.actions;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.util.Msg;
import vulnhunter4ghidra.VulnHunter4GhidraPlugin;
import vulnhunter4ghidra.engine.EngineProtocol;
import vulnhunter4ghidra.engine.EngineProtocol.Response;

public class AnalyzeTaintAction extends DockingAction {

	private final VulnHunter4GhidraPlugin plugin;

	public AnalyzeTaintAction(VulnHunter4GhidraPlugin plugin) {
		super("Analyze Taint Paths", plugin.getName());
		this.plugin = plugin;
		setMenuBarData(new MenuData(
			new String[] { "VulnHunter4Ghidra", "Analyze Taint" }, null, "VulnHunter"));
		plugin.getTool().addAction(this);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (!plugin.getEngineManager().isRunning()) {
			Msg.showError(this, null, "VulnHunter4Ghidra",
				"Engine is not running. Run 'Scan Functions' first.");
			return;
		}

		try {
			Response resp = plugin.getEngineManager().sendCommand(
				EngineProtocol.analyzeTaintCmd(5));
			if (resp.isOk()) {
				JsonObject data = resp.getData();
				long totalSources = data.get("total_sources").getAsLong();
				long totalSinks = data.get("total_sinks").getAsLong();
				long taintPaths = data.get("taint_paths").getAsLong();
				JsonArray findings = data.getAsJsonArray("findings");
				int findingsCount = findings != null ? findings.size() : 0;

				StringBuilder sb = new StringBuilder();
				sb.append(String.format("Sources: %d, Sinks: %d\n", totalSources, totalSinks));
				sb.append(String.format("Taint paths: %d, Findings: %d\n\n", taintPaths, findingsCount));

				if (findings != null) {
					for (JsonElement el : findings) {
						JsonObject f = el.getAsJsonObject();
						sb.append(String.format("[%s] %s — %s\n",
							f.get("severity").getAsString().toUpperCase(),
							f.get("cwe").getAsString(),
							f.get("title").getAsString()));
					}
				}

				Msg.showInfo(this, null, "VulnHunter4Ghidra — Results", sb.toString());
			} else {
				Msg.showError(this, null, "VulnHunter4Ghidra",
					"Analysis failed: " + resp.getMessage());
			}
		}
		catch (Exception e) {
			Msg.showError(this, null, "VulnHunter4Ghidra",
				"Error during taint analysis: " + e.getMessage(), e);
		}
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return true;
	}
}
