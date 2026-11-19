package vulnhunter4ghidra.actions;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import vulnhunter4ghidra.VulnHunter4GhidraPlugin;

public class ScanVulnsAction extends DockingAction {

	private final VulnHunter4GhidraPlugin plugin;

	public ScanVulnsAction(VulnHunter4GhidraPlugin plugin) {
		super("Scan for Vulnerabilities", plugin.getName());
		this.plugin = plugin;
		setMenuBarData(new MenuData(
			new String[] { "VulnHunter4Ghidra", "Scan Functions" }, null, "VulnHunter"));
		plugin.getTool().addAction(this);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		plugin.runScanOnlyTask();
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return plugin.getCurrentProgram() != null;
	}
}
