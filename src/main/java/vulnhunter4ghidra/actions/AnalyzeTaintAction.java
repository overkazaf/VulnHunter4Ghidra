package vulnhunter4ghidra.actions;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import vulnhunter4ghidra.VulnHunter4GhidraPlugin;

public class AnalyzeTaintAction extends DockingAction {

	private final VulnHunter4GhidraPlugin plugin;

	public AnalyzeTaintAction(VulnHunter4GhidraPlugin plugin) {
		super("Analyze Taint Paths", plugin.getName());
		this.plugin = plugin;
		setMenuBarData(new MenuData(
			new String[] { "VulnHunter4Ghidra", "Analyze Taint (Full Program)" }, null, "VulnHunter"));
		plugin.getTool().addAction(this);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		plugin.runFullAnalysisTask(
			plugin.getProvider().getSelectedMaxDepth(),
			plugin.getProvider().isSymbolicVerifyEnabled());
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return plugin.getCurrentProgram() != null;
	}
}
