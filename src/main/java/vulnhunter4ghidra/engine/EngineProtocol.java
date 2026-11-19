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

		public Command(String type, Map<String, Object> params) {
			this.type = type;
			this.params = params;
		}

		public String getType() { return type; }
		public Map<String, Object> getParams() { return params; }
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
			return data.get(key).getAsLong();
		}

		public boolean getDataBoolean(String key, boolean defaultValue) {
			if (data == null || !data.has(key)) return defaultValue;
			JsonElement el = data.get(key);
			return el.isJsonNull() ? defaultValue : el.getAsBoolean();
		}

		public JsonArray getDataArray(String key) {
			if (data == null || !data.has(key)) return null;
			return data.getAsJsonArray(key);
		}
	}

	public static String serialize(Command cmd) {
		return GSON.toJson(cmd);
	}

	public static Response deserialize(String json) {
		return GSON.fromJson(json, Response.class);
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

	public static Command scanFunctionsCmd(String functionsJson) {
		Map<String, Object> params = new HashMap<>();
		params.put("functions", GSON.fromJson(functionsJson, Object.class));
		return new Command("scan_functions", params);
	}

	public static Command scanFunctionCmd(
			String funcAddr, String funcName,
			String callsitesJson, String paramsJson, boolean isExported) {
		Map<String, Object> params = new HashMap<>();
		params.put("func_addr", funcAddr);
		params.put("func_name", funcName);
		params.put("callsites", GSON.fromJson(callsitesJson, Object.class));
		params.put("params", GSON.fromJson(paramsJson, Object.class));
		params.put("is_exported", isExported);
		return new Command("scan_function", params);
	}

	public static Command analyzeTaintCmd(int maxDepth) {
		Map<String, Object> params = new HashMap<>();
		params.put("max_depth", maxDepth);
		return new Command("analyze_taint", params);
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
