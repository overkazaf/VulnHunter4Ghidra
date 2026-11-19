package vulnhunter4ghidra.actions;

import docking.ActionContext;
import ghidra.app.context.NavigatableActionContext;

/**
 * Shared context gate that works uniformly in both the Listing and Decompiler views.
 */
public final class ActionContexts {

	private ActionContexts() {}

	public static NavigatableActionContext target(ActionContext context) {
		if (context instanceof NavigatableActionContext nav && nav.getAddress() != null) {
			return nav;
		}
		return null;
	}

	public static boolean isTarget(ActionContext context) {
		return target(context) != null;
	}
}
