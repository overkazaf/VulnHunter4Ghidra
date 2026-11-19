package vulnhunter4ghidra.actions;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.context.NavigatableActionContext;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import vulnhunter4ghidra.VulnHunter4GhidraPlugin;

/**
 * Right-click action (works in both Listing and Decompiler) to run targeted
 * intra-procedural vulnerability & taint analysis on the function under cursor.
 */
public class AnalyzeFunctionAction extends DockingAction {

	private final VulnHunter4GhidraPlugin plugin;

	public AnalyzeFunctionAction(VulnHunter4GhidraPlugin plugin) {
		super("Analyze Current Function", plugin.getName());
		this.plugin = plugin;
		setPopupMenuData(new MenuData(
			new String[] { "VulnHunter4Ghidra", "Analyze Current Function" }, null, "VulnHunter"));
		setMenuBarData(new MenuData(
			new String[] { "VulnHunter4Ghidra", "Analyze Current Function" }, null, "VulnHunter"));
		plugin.getTool().addAction(this);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return ActionContexts.isTarget(context);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		NavigatableActionContext nav = ActionContexts.target(context);
		if (nav == null) {
			return;
		}
		Program program = nav.getProgram();
		Function func = program != null
			? program.getFunctionManager().getFunctionContaining(nav.getAddress())
			: null;
		if (func == null) {
			Msg.showWarn(this, null, "VulnHunter4Ghidra",
				"No function contains address " + nav.getAddress());
			return;
		}
		plugin.runSingleFunctionAnalysisTask(func);
	}
}
