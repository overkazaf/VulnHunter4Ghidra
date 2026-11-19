package vulnhunter4ghidra.actions;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.context.NavigatableActionContext;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import vulnhunter4ghidra.VulnHunter4GhidraPlugin;

/**
 * Context-menu action allowing analysts to mark a callsite or function as a
 * Custom Source, Custom Sink, or Sanitizer directly from Listing or Decompiler.
 */
public class MarkCustomNodeAction extends DockingAction {

	private final VulnHunter4GhidraPlugin plugin;
	private final String role;

	public MarkCustomNodeAction(VulnHunter4GhidraPlugin plugin, String role, String menuLabel) {
		super("Mark VulnHunter " + role, plugin.getName());
		this.plugin = plugin;
		this.role = role;
		setPopupMenuData(new MenuData(
			new String[] { "VulnHunter4Ghidra", menuLabel }, null, "VulnHunterCustom"));
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
		Address addr = nav.getAddress();
		if (program == null || addr == null) {
			return;
		}

		String calleeName = null;
		Instruction instr = program.getListing().getInstructionContaining(addr);
		if (instr != null && instr.getFlowType().isCall()) {
			for (var ref : instr.getReferencesFrom()) {
				if (ref.getReferenceType().isCall()) {
					Function callee = program.getFunctionManager().getFunctionAt(ref.getToAddress());
					if (callee != null) {
						calleeName = callee.getName();
						break;
					}
				}
			}
		}
		if (calleeName == null) {
			Function fn = program.getFunctionManager().getFunctionAt(addr);
			if (fn != null) {
				calleeName = fn.getName();
			}
		}

		String addrHex = "0x" + Long.toHexString(addr.getOffset());
		plugin.markCustomNodeTask(role, calleeName, addrHex);
	}
}
