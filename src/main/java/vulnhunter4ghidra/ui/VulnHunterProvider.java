package vulnhunter4ghidra.ui;

import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import docking.ComponentProvider;
import ghidra.app.services.GoToService;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import vulnhunter4ghidra.VulnHunter4GhidraPlugin;
import vulnhunter4ghidra.engine.EngineProtocol;
import vulnhunter4ghidra.engine.EngineProtocol.Response;

/**
 * Dockable VulnHunter4Ghidra analysis workbench: sortable/filterable Findings table,
 * Sources/Sinks inventory, step-by-step Taint Path tree with one-click navigation
 * and Listing/Decompiler highlighting, Bookmark triage persistence, and report export.
 */
public class VulnHunterProvider extends ComponentProvider {

	private static final String BOOKMARK_CATEGORY = "VulnHunter";
	private static final Gson PRETTY_GSON = new GsonBuilder().setPrettyPrinting().create();

	private final VulnHunter4GhidraPlugin plugin;

	private JPanel mainPanel;
	private JTabbedPane tabbedPane;
	private JSpinner depthSpinner;
	private JCheckBox verifyCheckBox;
	private JComboBox<String> severityFilterCombo;
	private JTextField searchField;
	private JLabel statusLabel;

	private DefaultTableModel findingsModel;
	private JTable findingsTable;
	private TableRowSorter<DefaultTableModel> findingsSorter;
	private final List<JsonObject> rawFindings = new ArrayList<>();

	private DefaultTableModel sourcesModel;
	private JTable sourcesTable;

	private DefaultTableModel sinksModel;
	private JTable sinksTable;

	private DefaultMutableTreeNode pathRoot;
	private DefaultTreeModel pathTreeModel;
	private JTree pathTree;
	private JTextArea detailArea;

	private record PathHopNode(String label, String addressHex) {
		@Override
		public String toString() {
			return label;
		}
	}

	public VulnHunterProvider(VulnHunter4GhidraPlugin plugin) {
		super(plugin.getTool(), "VulnHunter4Ghidra", plugin.getName());
		this.plugin = plugin;
		buildComponent();
		setTitle("VulnHunter4Ghidra — Taint & CWE Workbench");
		setVisible(true);
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	public int getSelectedMaxDepth() {
		return (Integer) depthSpinner.getValue();
	}

	public boolean isSymbolicVerifyEnabled() {
		return verifyCheckBox.isSelected();
	}

	public void setStatus(String status) {
		SwingUtilities.invokeLater(() -> statusLabel.setText(status));
	}

	private void buildComponent() {
		mainPanel = new JPanel(new BorderLayout(4, 4));
		mainPanel.add(buildToolbarPanel(), BorderLayout.NORTH);

		tabbedPane = new JTabbedPane();
		tabbedPane.addTab("Findings (0)", buildFindingsPanel());
		tabbedPane.addTab("Sources (0)", buildSourcesPanel());
		tabbedPane.addTab("Sinks (0)", buildSinksPanel());

		JSplitPane splitPane = new JSplitPane(
			JSplitPane.VERTICAL_SPLIT, tabbedPane, buildInspectorPanel());
		splitPane.setResizeWeight(0.65);

		statusLabel = new JLabel("Ready — Open a binary and click 'Scan & Analyze'");
		statusLabel.setBorder(BorderFactory.createEmptyBorder(3, 6, 3, 6));

		mainPanel.add(splitPane, BorderLayout.CENTER);
		mainPanel.add(statusLabel, BorderLayout.SOUTH);
	}

	private JPanel buildToolbarPanel() {
		JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));

		JButton runBtn = new JButton("Scan & Analyze");
		runBtn.addActionListener(e -> plugin.runFullAnalysisTask(
			getSelectedMaxDepth(), isSymbolicVerifyEnabled()));
		bar.add(runBtn);

		bar.add(new JLabel("Depth:"));
		depthSpinner = new JSpinner(new SpinnerNumberModel(5, 1, 15, 1));
		bar.add(depthSpinner);

		verifyCheckBox = new JCheckBox("Z3 Verify");
		verifyCheckBox.setToolTipText("Verify candidate taint paths with bounded Z3 symbolic feasibility");
		bar.add(verifyCheckBox);

		bar.add(new JLabel("Severity:"));
		severityFilterCombo = new JComboBox<>(new String[] { "All", "Critical", "High+", "Medium+" });
		severityFilterCombo.addActionListener(e -> applyFindingsFilter());
		bar.add(severityFilterCombo);

		bar.add(new JLabel("Filter:"));
		searchField = new JTextField(14);
		searchField.setToolTipText("Filter by CWE, function, callee, status, or title");
		searchField.getDocument().addDocumentListener(new DocumentListener() {
			@Override public void insertUpdate(DocumentEvent e) { applyFindingsFilter(); }
			@Override public void removeUpdate(DocumentEvent e) { applyFindingsFilter(); }
			@Override public void changedUpdate(DocumentEvent e) { applyFindingsFilter(); }
		});
		bar.add(searchField);

		JButton loadRulesBtn = new JButton("Load Rules...");
		loadRulesBtn.addActionListener(e -> promptLoadRules());
		bar.add(loadRulesBtn);

		JButton clearHlBtn = new JButton("Clear Highlights");
		clearHlBtn.addActionListener(e -> plugin.clearHighlights());
		bar.add(clearHlBtn);

		JButton exportBtn = new JButton("Export...");
		exportBtn.addActionListener(e -> promptExportReport());
		bar.add(exportBtn);

		return bar;
	}

	private JPanel buildFindingsPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		findingsModel = new DefaultTableModel(
			new String[] {
				"ID", "Severity", "Confidence", "Verified",
				"CWE", "Function", "Sink", "Triage", "Title"
			}, 0) {
			@Override
			public boolean isCellEditable(int row, int column) {
				return false;
			}
		};

		findingsTable = new JTable(findingsModel);
		findingsTable.setFillsViewportHeight(true);
		findingsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		findingsSorter = new TableRowSorter<>(findingsModel);
		findingsTable.setRowSorter(findingsSorter);
		findingsTable.setComponentPopupMenu(buildFindingsPopupMenu());

		findingsTable.getSelectionModel().addListSelectionListener(e -> {
			if (!e.getValueIsAdjusting()) {
				onFindingSelected();
			}
		});

		panel.add(new JScrollPane(findingsTable), BorderLayout.CENTER);
		return panel;
	}

	private JPopupMenu buildFindingsPopupMenu() {
		JPopupMenu menu = new JPopupMenu();

		JMenuItem goSource = new JMenuItem("Go to Source");
		goSource.addActionListener(e -> jumpSelectedFindingEndpoint(true));
		menu.add(goSource);

		JMenuItem goSink = new JMenuItem("Go to Sink");
		goSink.addActionListener(e -> jumpSelectedFindingEndpoint(false));
		menu.add(goSink);

		menu.addSeparator();

		JMenuItem markConfirmed = new JMenuItem("Mark as Confirmed (Bookmark)");
		markConfirmed.addActionListener(e -> updateSelectedFindingTriage("CONFIRMED"));
		menu.add(markConfirmed);

		JMenuItem markFp = new JMenuItem("Mark as False Positive (Bookmark)");
		markFp.addActionListener(e -> updateSelectedFindingTriage("FALSE_POSITIVE"));
		menu.add(markFp);

		menu.addSeparator();

		JMenuItem copyJson = new JMenuItem("Copy Finding JSON");
		copyJson.addActionListener(e -> copySelectedFindingJson());
		menu.add(copyJson);

		return menu;
	}

	private JPanel buildSourcesPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		sourcesModel = new DefaultTableModel(
			new String[] { "Type", "Function", "Address", "Description" }, 0) {
			@Override
			public boolean isCellEditable(int row, int col) {
				return false;
			}
		};
		sourcesTable = new JTable(sourcesModel);
		sourcesTable.setAutoCreateRowSorter(true);
		sourcesTable.setFillsViewportHeight(true);
		sourcesTable.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() >= 2) {
					int row = sourcesTable.getSelectedRow();
					if (row >= 0) {
						int mrow = sourcesTable.convertRowIndexToModel(row);
						navigateToHex((String) sourcesModel.getValueAt(mrow, 2));
					}
				}
			}
		});
		panel.add(new JScrollPane(sourcesTable), BorderLayout.CENTER);
		return panel;
	}

	private JPanel buildSinksPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		sinksModel = new DefaultTableModel(
			new String[] { "Type", "CWE", "Function", "Callee", "Address" }, 0) {
			@Override
			public boolean isCellEditable(int row, int col) {
				return false;
			}
		};
		sinksTable = new JTable(sinksModel);
		sinksTable.setAutoCreateRowSorter(true);
		sinksTable.setFillsViewportHeight(true);
		sinksTable.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() >= 2) {
					int row = sinksTable.getSelectedRow();
					if (row >= 0) {
						int mrow = sinksTable.convertRowIndexToModel(row);
						navigateToHex((String) sinksModel.getValueAt(mrow, 4));
					}
				}
			}
		});
		panel.add(new JScrollPane(sinksTable), BorderLayout.CENTER);
		return panel;
	}

	private JComponent buildInspectorPanel() {
		pathRoot = new DefaultMutableTreeNode("Select a finding to inspect taint path");
		pathTreeModel = new DefaultTreeModel(pathRoot);
		pathTree = new JTree(pathTreeModel);
		pathTree.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
		pathTree.setShowsRootHandles(true);
		pathTree.addTreeSelectionListener(e -> {
			Object nodeObj = pathTree.getLastSelectedPathComponent();
			if (nodeObj instanceof DefaultMutableTreeNode treeNode
					&& treeNode.getUserObject() instanceof PathHopNode hop
					&& hop.addressHex() != null) {
				navigateToHex(hop.addressHex());
			}
		});

		detailArea = new JTextArea();
		detailArea.setEditable(false);
		detailArea.setLineWrap(true);
		detailArea.setWrapStyleWord(true);
		detailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

		JSplitPane inspectorSplit = new JSplitPane(
			JSplitPane.HORIZONTAL_SPLIT,
			new JScrollPane(pathTree),
			new JScrollPane(detailArea));
		inspectorSplit.setResizeWeight(0.45);
		return inspectorSplit;
	}

	public void updateInventory(JsonArray sources, JsonArray sinks) {
		SwingUtilities.invokeLater(() -> {
			sourcesModel.setRowCount(0);
			if (sources != null) {
				for (JsonElement el : sources) {
					JsonObject s = el.getAsJsonObject();
					sourcesModel.addRow(new Object[] {
						str(s, "source_type"),
						str(s, "func_name"),
						str(s, "address"),
						str(s, "description")
					});
				}
			}
			tabbedPane.setTitleAt(1, "Sources (" + sourcesModel.getRowCount() + ")");

			sinksModel.setRowCount(0);
			if (sinks != null) {
				for (JsonElement el : sinks) {
					JsonObject s = el.getAsJsonObject();
					sinksModel.addRow(new Object[] {
						str(s, "sink_type"),
						str(s, "cwe"),
						str(s, "func_name"),
						str(s, "callee_name"),
						str(s, "address")
					});
				}
			}
			tabbedPane.setTitleAt(2, "Sinks (" + sinksModel.getRowCount() + ")");
		});
	}

	public void updateFindings(JsonArray findings) {
		SwingUtilities.invokeLater(() -> {
			rawFindings.clear();
			findingsModel.setRowCount(0);
			Program program = plugin.getCurrentProgram();

			if (findings != null) {
				for (JsonElement el : findings) {
					JsonObject f = el.getAsJsonObject();
					rawFindings.add(f);

					JsonObject tp = f.getAsJsonObject("taint_path");
					JsonObject snk = tp != null ? tp.getAsJsonObject("sink") : null;
					String sinkAddrHex = snk != null ? str(snk, "address") : "";
					String triage = readBookmarkTriage(program, sinkAddrHex, str(f, "cwe"));

					findingsModel.addRow(new Object[] {
						f.has("finding_id") ? f.get("finding_id").getAsInt() : rawFindings.size(),
						str(f, "severity").toUpperCase(),
						str(f, "confidence").toUpperCase(),
						f.has("verified") && f.get("verified").getAsBoolean() ? "YES" : "NO",
						str(f, "cwe"),
						snk != null ? str(snk, "func_name") : "",
						snk != null ? str(snk, "callee_name") + " @ " + sinkAddrHex : "",
						triage,
						str(f, "title")
					});
				}
			}
			tabbedPane.setTitleAt(0, "Findings (" + rawFindings.size() + ")");
			tabbedPane.setSelectedIndex(0);
			setVisible(true);
			toFront();
			if (!rawFindings.isEmpty()) {
				findingsTable.setRowSelectionInterval(0, 0);
			}
		});
	}

	private void applyFindingsFilter() {
		String sevMode = (String) severityFilterCombo.getSelectedItem();
		String query = searchField.getText() != null ? searchField.getText().trim().toLowerCase() : "";

		findingsSorter.setRowFilter(new RowFilter<>() {
			@Override
			public boolean include(Entry<? extends DefaultTableModel, ? extends Integer> entry) {
				String sev = String.valueOf(entry.getValue(1));
				if ("Critical".equals(sevMode) && !"CRITICAL".equals(sev)) {
					return false;
				}
				if ("High+".equals(sevMode) && !("CRITICAL".equals(sev) || "HIGH".equals(sev))) {
					return false;
				}
				if ("Medium+".equals(sevMode)
						&& !("CRITICAL".equals(sev) || "HIGH".equals(sev) || "MEDIUM".equals(sev))) {
					return false;
				}
				if (!query.isEmpty()) {
					for (int i = 0; i < entry.getValueCount(); i++) {
						if (String.valueOf(entry.getValue(i)).toLowerCase().contains(query)) {
							return true;
						}
					}
					return false;
				}
				return true;
			}
		});
	}

	private JsonObject getSelectedFinding() {
		int viewRow = findingsTable.getSelectedRow();
		if (viewRow < 0) {
			return null;
		}
		int modelRow = findingsTable.convertRowIndexToModel(viewRow);
		if (modelRow < 0 || modelRow >= rawFindings.size()) {
			return null;
		}
		return rawFindings.get(modelRow);
	}

	private void onFindingSelected() {
		JsonObject f = getSelectedFinding();
		if (f == null) {
			return;
		}

		JsonObject tp = f.getAsJsonObject("taint_path");
		JsonObject src = tp.getAsJsonObject("source");
		JsonObject snk = tp.getAsJsonObject("sink");
		String srcHex = str(src, "address");
		String snkHex = str(snk, "address");

		// Populate path tree
		pathRoot.removeAllChildren();
		pathRoot.setUserObject(str(f, "cwe") + " — " + str(f, "title"));

		pathRoot.add(new DefaultMutableTreeNode(new PathHopNode(
			"[SOURCE] " + str(src, "func_name") + " @ " + srcHex + " (" + str(src, "description") + ")",
			srcHex)));

		List<Address> hopAddresses = new ArrayList<>();
		Program program = plugin.getCurrentProgram();
		JsonArray pathAddrs = tp.getAsJsonArray("path_addrs");
		JsonArray pathFuncs = tp.getAsJsonArray("path_funcs");
		if (pathAddrs != null) {
			for (int i = 0; i < pathAddrs.size(); i++) {
				String hopHex = pathAddrs.get(i).getAsString();
				String fnLabel = (pathFuncs != null && i < pathFuncs.size())
					? pathFuncs.get(i).getAsString()
					: "block";
				pathRoot.add(new DefaultMutableTreeNode(new PathHopNode(
					String.format("  [HOP %d] %s @ %s", i + 1, fnLabel, hopHex), hopHex)));
				Address hopAddr = parseAddress(program, hopHex);
				if (hopAddr != null) {
					hopAddresses.add(hopAddr);
				}
			}
		}

		pathRoot.add(new DefaultMutableTreeNode(new PathHopNode(
			"[SINK]   " + str(snk, "callee_name") + "() in " + str(snk, "func_name") + " @ " + snkHex,
			snkHex)));
		pathTreeModel.reload();
		for (int i = 0; i < pathTree.getRowCount(); i++) {
			pathTree.expandRow(i);
		}

		// Populate details & evidence
		StringBuilder sb = new StringBuilder();
		sb.append("CWE:         ").append(str(f, "cwe"))
		  .append("  |  Severity: ").append(str(f, "severity").toUpperCase())
		  .append("  |  Confidence: ").append(str(f, "confidence").toUpperCase()).append("\n");
		sb.append("Verified:    ").append(f.has("verified") && f.get("verified").getAsBoolean() ? "Z3 Satisfiable" : "Static Data-Flow")
		  .append("  |  Fingerprint: ").append(str(f, "fingerprint")).append("\n\n");
		sb.append("Description:\n  ").append(str(f, "description")).append("\n\n");
		if (f.has("evidence") && f.get("evidence").isJsonArray()) {
			sb.append("Analysis Evidence:\n");
			for (JsonElement ev : f.getAsJsonArray("evidence")) {
				sb.append("  • ").append(ev.getAsString()).append("\n");
			}
		}
		detailArea.setText(sb.toString());
		detailArea.setCaretPosition(0);

		// Highlight path and jump to sink
		if (program != null) {
			Address srcAddr = parseAddress(program, srcHex);
			Address snkAddr = parseAddress(program, snkHex);
			plugin.getHighlighter().highlightTaintPath(program, srcAddr, hopAddresses, snkAddr);
			if (snkAddr != null) {
				navigateToAddress(snkAddr);
			}
		}
	}

	private void jumpSelectedFindingEndpoint(boolean toSource) {
		JsonObject f = getSelectedFinding();
		if (f == null) return;
		JsonObject tp = f.getAsJsonObject("taint_path");
		JsonObject node = tp.getAsJsonObject(toSource ? "source" : "sink");
		navigateToHex(str(node, "address"));
	}

	private void updateSelectedFindingTriage(String triageState) {
		int viewRow = findingsTable.getSelectedRow();
		if (viewRow < 0) return;
		int modelRow = findingsTable.convertRowIndexToModel(viewRow);
		JsonObject f = rawFindings.get(modelRow);
		JsonObject snk = f.getAsJsonObject("taint_path").getAsJsonObject("sink");
		String sinkHex = str(snk, "address");
		String cwe = str(f, "cwe");

		Program program = plugin.getCurrentProgram();
		Address addr = parseAddress(program, sinkHex);
		if (program != null && addr != null) {
			int txId = program.startTransaction("VulnHunter4Ghidra triage bookmark");
			try {
				BookmarkManager bm = program.getBookmarkManager();
				bm.setBookmark(addr, BookmarkType.ANALYSIS, BOOKMARK_CATEGORY,
					"[" + triageState + "] " + cwe + " — " + str(f, "title"));
			}
			finally {
				program.endTransaction(txId, true);
			}
		}
		findingsModel.setValueAt(triageState, modelRow, 7);
		setStatus("Marked finding #" + (modelRow + 1) + " as " + triageState);
	}

	private String readBookmarkTriage(Program program, String sinkHex, String cwe) {
		Address addr = parseAddress(program, sinkHex);
		if (program == null || addr == null) {
			return "UNREVIEWED";
		}
		Bookmark[] bookmarks = program.getBookmarkManager().getBookmarks(addr, BookmarkType.ANALYSIS);
		for (Bookmark b : bookmarks) {
			if (BOOKMARK_CATEGORY.equals(b.getCategory()) && b.getComment() != null) {
				if (b.getComment().contains("[CONFIRMED]") && b.getComment().contains(cwe)) {
					return "CONFIRMED";
				}
				if (b.getComment().contains("[FALSE_POSITIVE]") && b.getComment().contains(cwe)) {
					return "FALSE_POSITIVE";
				}
			}
		}
		return "UNREVIEWED";
	}

	private void copySelectedFindingJson() {
		JsonObject f = getSelectedFinding();
		if (f == null) return;
		Toolkit.getDefaultToolkit().getSystemClipboard()
			.setContents(new StringSelection(PRETTY_GSON.toJson(f)), null);
		setStatus("Copied finding JSON to clipboard");
	}

	private void promptLoadRules() {
		JFileChooser chooser = new JFileChooser();
		chooser.setDialogTitle("Select VulnHunter Rules File (.toml / .json)");
		if (chooser.showOpenDialog(mainPanel) == JFileChooser.APPROVE_OPTION) {
			File ruleFile = chooser.getSelectedFile();
			plugin.loadCustomRulesTask(ruleFile.getAbsolutePath());
		}
	}

	private void promptExportReport() {
		if (rawFindings.isEmpty()) {
			Msg.showInfo(this, mainPanel, "VulnHunter4Ghidra", "No findings to export yet.");
			return;
		}
		JFileChooser chooser = new JFileChooser();
		chooser.setDialogTitle("Export Vulnerability Report (.sarif or .json)");
		chooser.setSelectedFile(new File("vulnhunter-report.sarif"));
		if (chooser.showSaveDialog(mainPanel) == JFileChooser.APPROVE_OPTION) {
			File out = chooser.getSelectedFile();
			try {
				String content;
				if (out.getName().endsWith(".sarif")) {
					Response resp = plugin.getEngineManager().sendCommand(EngineProtocol.exportSarifCmd());
					if (resp.isOk() && resp.getData() != null && resp.getData().has("sarif")) {
						content = PRETTY_GSON.toJson(resp.getData().get("sarif"));
					}
					else {
						JsonObject wrapper = new JsonObject();
						JsonArray arr = new JsonArray();
						rawFindings.forEach(arr::add);
						wrapper.add("findings", arr);
						content = PRETTY_GSON.toJson(wrapper);
					}
				}
				else {
					JsonObject wrapper = new JsonObject();
					JsonArray arr = new JsonArray();
					rawFindings.forEach(arr::add);
					wrapper.add("findings", arr);
					content = PRETTY_GSON.toJson(wrapper);
				}
				Files.writeString(out.toPath(), content, StandardCharsets.UTF_8);
				setStatus("Exported report to " + out.getAbsolutePath());
			}
			catch (Exception ex) {
				Msg.showError(this, mainPanel, "VulnHunter4Ghidra",
					"Failed to export report: " + ex.getMessage(), ex);
			}
		}
	}

	private void navigateToHex(String hexAddr) {
		Program program = plugin.getCurrentProgram();
		Address addr = parseAddress(program, hexAddr);
		if (addr != null) {
			navigateToAddress(addr);
		}
	}

	private void navigateToAddress(Address addr) {
		GoToService goTo = plugin.getTool().getService(GoToService.class);
		if (goTo != null) {
			goTo.goTo(addr);
		}
	}

	private static Address parseAddress(Program program, String hexAddr) {
		if (program == null || hexAddr == null || hexAddr.isBlank()) {
			return null;
		}
		try {
			String clean = hexAddr.startsWith("0x") || hexAddr.startsWith("0X")
				? hexAddr.substring(2)
				: hexAddr;
			long offset = Long.parseUnsignedLong(clean, 16);
			return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
		}
		catch (Exception e) {
			return null;
		}
	}

	private static String str(JsonObject obj, String key) {
		if (obj == null || !obj.has(key) || obj.get(key).isJsonNull()) {
			return "";
		}
		return obj.get(key).getAsString();
	}
}
