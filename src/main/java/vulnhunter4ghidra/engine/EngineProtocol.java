package vulnhunter4ghidra.engine;

import java.util.HashMap;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

public class EngineProtocol {

	private static final Gson GSON = new GsonBuilder().create();

	public static class Command {
		private final String type;
		private final Map<String, Object> params;
		private String token;

		public Command(String type, Map<String, Object> params) {
			this.type = type;
			this.params = params;
		}

		public String getType() { return type; }
		public Map<String, Object> getParams() { return params; }
		public String getToken() { return token; }
		public void setToken(String token) { this.token = token; }
	}

	public static class Response {
		private String status;
		private JsonObject data;
		private String message;

		public boolean isOk() { return "ok".equals(status); }
		public boolean isError() { return "error".equals(status); }
		public boolean isProgress() { return "progress".equals(status); }
		public String getStatus() { return status; }
		public JsonObject getData() { return data; }
		public String getMessage() { return message; }

		public String getDataString(String key) {
			if (data == null || !data.has(key)) return null;
			JsonElement el = data.get(key);
			return el.isJsonNull() ? null : el.getAsString();
		}

		public long getDataLong(String key, long defaultValue) {
			if (data == null || !data.has(key)) return defaultValue;
			JsonElement el = data.get(key);
			return el.isJsonNull() ? defaultValue : el.getAsLong();
		}

		public boolean getDataBoolean(String key, boolean defaultValue) {
			if (data == null || !data.has(key)) return defaultValue;
			JsonElement el = data.get(key);
			return el.isJsonNull() ? defaultValue : el.getAsBoolean();
		}

		public JsonArray getDataArray(String key) {
			if (data == null || !data.has(key) || data.get(key).isJsonNull()) return null;
			return data.getAsJsonArray(key);
		}
	}

	public static String serialize(Command cmd) {
		return GSON.toJson(cmd);
	}

	public static Response deserialize(String json) {
		return GSON.fromJson(json, Response.class);
	}

	public static Command pingCmd() {
		return new Command("ping", new HashMap<>());
	}

	public static Command shutdownCmd() {
		return new Command("shutdown", new HashMap<>());
	}

	public static Command cancelCmd() {
		return new Command("cancel", new HashMap<>());
	}

	public static Command clearScanCmd() {
		return new Command("clear_scan", new HashMap<>());
	}

	public static Command initCmd(String binaryPath) {
		return initCmd(binaryPath, null);
	}

	public static Command initCmd(String binaryPath, String baseAddr) {
		Map<String, Object> params = new HashMap<>();
		params.put("binary_path", binaryPath);
		if (baseAddr != null && !baseAddr.isBlank()) {
			params.put("base_addr", baseAddr);
		}
		return new Command("init", params);
	}

	public static Command scanFunctionsCmd(JsonArray functions, boolean replace) {
		Map<String, Object> params = new HashMap<>();
		params.put("functions", functions);
		params.put("replace", replace);
		return new Command("scan_functions", params);
	}

	public static Command scanFunctionsCmd(String functionsJson) {
		Map<String, Object> params = new HashMap<>();
		params.put("functions", GSON.fromJson(functionsJson, Object.class));
		params.put("replace", true);
		return new Command("scan_functions", params);
	}

	public static Command scanFunctionCmd(JsonObject funcObj) {
		Map<String, Object> params = new HashMap<>();
		params.put("func_addr", funcObj.get("func_addr").getAsString());
		params.put("func_name", funcObj.get("func_name").getAsString());
		params.put("callsites", funcObj.getAsJsonArray("callsites"));
		params.put("params", funcObj.getAsJsonArray("params"));
		params.put("is_exported", funcObj.get("is_exported").getAsBoolean());
		return new Command("scan_function", params);
	}

	public static Command analyzeTaintCmd(int maxDepth) {
		return analyzeTaintCmd(maxDepth, null, false);
	}

	public static Command analyzeTaintCmd(int maxDepth, String funcAddrHex, boolean verify) {
		Map<String, Object> params = new HashMap<>();
		params.put("max_depth", maxDepth);
		params.put("verify", verify);
		if (funcAddrHex != null && !funcAddrHex.isBlank()) {
			params.put("func_addr", funcAddrHex);
		}
		return new Command("analyze_taint", params);
	}

	public static Command markCustomCmd(
			String role, String funcName, String addrHex,
			String cwe, String sinkType, int vulnerableArgIndex) {
		Map<String, Object> params = new HashMap<>();
		params.put("role", role);
		if (funcName != null && !funcName.isBlank()) {
			params.put("func_name", funcName);
		}
		if (addrHex != null && !addrHex.isBlank()) {
			params.put("address", addrHex);
		}
		if (cwe != null) {
			params.put("cwe", cwe);
		}
		if (sinkType != null) {
			params.put("sink_type", sinkType);
		}
		params.put("vulnerable_arg_index", vulnerableArgIndex);
		return new Command("mark_custom", params);
	}

	public static Command loadRulesCmd(String rulesPath) {
		Map<String, Object> params = new HashMap<>();
		params.put("path", rulesPath);
		return new Command("load_rules", params);
	}

	public static Command exportSarifCmd() {
		return new Command("export_sarif", new HashMap<>());
	}

	public static Command getFindingsCmd() {
		return new Command("get_findings", new HashMap<>());
	}

	public static Command getSourcesCmd() {
		return new Command("get_sources", new HashMap<>());
	}

	public static Command getSinksCmd() {
		return new Command("get_sinks", new HashMap<>());
	}
}
