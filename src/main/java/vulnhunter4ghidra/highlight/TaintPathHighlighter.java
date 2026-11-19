package vulnhunter4ghidra.highlight;

import java.awt.Color;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * Highlights Source, intermediate Taint Path blocks/functions, and Sink addresses
 * in Ghidra's Listing and Decompiler views via {@link ColorizingService}.
 */
public class TaintPathHighlighter {

	private static final Color SOURCE_COLOR = new Color(30, 136, 229, 95);
	private static final Color PATH_COLOR = new Color(255, 193, 7, 75);
	private static final Color SINK_COLOR = new Color(229, 57, 53, 110);

	private final PluginTool tool;
	private final List<AddressRangeRecord> activeHighlights = new ArrayList<>();

	private record AddressRangeRecord(Address min, Address max) {}

	public TaintPathHighlighter(PluginTool tool) {
		this.tool = tool;
	}

	public void highlightTaintPath(Program program, Address sourceAddr,
			List<Address> pathAddrs, Address sinkAddr) {
		if (program == null) {
			return;
		}
		ColorizingService service = tool.getService(ColorizingService.class);
		if (service == null) {
			return;
		}

		int txId = program.startTransaction("VulnHunter4Ghidra highlight taint path");
		try {
			clearInternal(service);
			if (pathAddrs != null) {
				for (Address hop : pathAddrs) {
					if (hop != null) {
						paintCodeUnitOrBlock(program, service, hop, PATH_COLOR);
					}
				}
			}
			if (sourceAddr != null) {
				paintInstruction(program, service, sourceAddr, SOURCE_COLOR);
			}
			if (sinkAddr != null) {
				paintInstruction(program, service, sinkAddr, SINK_COLOR);
			}
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	public void clearHighlights(Program program) {
		if (program == null || activeHighlights.isEmpty()) {
			activeHighlights.clear();
			return;
		}
		ColorizingService service = tool.getService(ColorizingService.class);
		if (service == null) {
			activeHighlights.clear();
			return;
		}
		int txId = program.startTransaction("VulnHunter4Ghidra clear highlights");
		try {
			clearInternal(service);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	private void clearInternal(ColorizingService service) {
		for (AddressRangeRecord rec : activeHighlights) {
			service.clearBackgroundColor(rec.min(), rec.max());
		}
		activeHighlights.clear();
	}

	private void paintInstruction(Program program, ColorizingService service,
			Address addr, Color color) {
		CodeUnit cu = program.getListing().getCodeUnitContaining(addr);
		Address min = cu != null ? cu.getMinAddress() : addr;
		Address max = cu != null ? cu.getMaxAddress() : addr;
		service.setBackgroundColor(min, max, color);
		activeHighlights.add(new AddressRangeRecord(min, max));
	}

	private void paintCodeUnitOrBlock(Program program, ColorizingService service,
			Address addr, Color color) {
		Function fn = program.getFunctionManager().getFunctionAt(addr);
		if (fn != null) {
			// For inter-procedural hops where hop is a function entry, highlight the entry instruction
			paintInstruction(program, service, fn.getEntryPoint(), color);
			return;
		}
		paintInstruction(program, service, addr, color);
	}
}
