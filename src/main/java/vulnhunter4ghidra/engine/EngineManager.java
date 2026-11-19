package vulnhunter4ghidra.engine;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.util.Msg;
import vulnhunter4ghidra.engine.EngineProtocol.Command;
import vulnhunter4ghidra.engine.EngineProtocol.Response;

/**
 * Manages the lifecycle and JSON-line stdio RPC channel of the dedicated Python
 * analysis subprocess. Using per-instance stdio pipes avoids TCP port collisions
 * across multiple Ghidra instances and prevents unauthorized local socket access.
 */
public class EngineManager {

	private Process pythonProcess;
	private BufferedWriter writer;
	private BufferedReader reader;
	private String sessionToken;
	private final ExecutorService executor = Executors.newSingleThreadExecutor();
	private volatile boolean running;

	public synchronized void start() throws IOException {
		if (isRunning()) {
			return;
		}
		stop();

		String pythonPath = findPython();
		String serverModule = findServerModule();
		byte[] tokenBytes = new byte[16];
		new SecureRandom().nextBytes(tokenBytes);
		sessionToken = HexFormat.of().formatHex(tokenBytes);

		ProcessBuilder pb = new ProcessBuilder(
			pythonPath, "-m", "vulnhunter4ghidra_engine.server",
			"--stdio", "--auth-token", sessionToken);
		pb.environment().put("PYTHONPATH", serverModule);
		pb.redirectErrorStream(false);
		pythonProcess = pb.start();

		startLogReader(pythonProcess.getErrorStream());
		writer = new BufferedWriter(
			new OutputStreamWriter(pythonProcess.getOutputStream(), StandardCharsets.UTF_8));
		reader = new BufferedReader(
			new InputStreamReader(pythonProcess.getInputStream(), StandardCharsets.UTF_8));
		running = true;

		Response ping = sendCommand(EngineProtocol.pingCmd());
		if (!ping.isOk()) {
			stop();
			throw new IOException("Engine handshake failed: " + ping.getMessage());
		}
		Msg.info(this, "VulnHunter4Ghidra engine started (stdio session)");
	}

	public synchronized void stop() {
		if (running && writer != null) {
			try {
				Command shutdown = EngineProtocol.shutdownCmd();
				shutdown.setToken(sessionToken);
				writer.write(EngineProtocol.serialize(shutdown));
				writer.newLine();
				writer.flush();
			}
			catch (IOException ignored) {
				// Process may have already exited
			}
		}
		running = false;
		closeStreams();
		if (pythonProcess != null && pythonProcess.isAlive()) {
			pythonProcess.destroy();
			try {
				if (!pythonProcess.waitFor(3, TimeUnit.SECONDS)) {
					pythonProcess.destroyForcibly();
				}
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				pythonProcess.destroyForcibly();
			}
		}
		pythonProcess = null;
		sessionToken = null;
	}

	public boolean isRunning() {
		return running && pythonProcess != null && pythonProcess.isAlive()
			&& writer != null && reader != null;
	}

	public void requestCancel() {
		// Cancellation runs best-effort; if stdio lock is held by an active command,
		// restarting the engine cleanly aborts long native analyses when cancelled by user.
		if (!isRunning()) {
			return;
		}
		if (pythonProcess != null && pythonProcess.isAlive()) {
			Msg.warn(this, "Aborting active engine task on user cancellation");
			stop();
		}
	}

	public Response sendCommand(Command cmd) throws IOException {
		return sendCommandWithProgress(cmd, null);
	}

	public CompletableFuture<Response> sendCommandAsync(Command cmd) {
		return CompletableFuture.supplyAsync(() -> {
			try {
				return sendCommand(cmd);
			}
			catch (IOException e) {
				throw new RuntimeException(e);
			}
		}, executor);
	}

	public Response sendCommandWithProgress(Command cmd,
			Consumer<Response> onProgress) throws IOException {
		if (!isRunning()) {
			throw new IOException("Engine is not running");
		}
		cmd.setToken(sessionToken);
		String json = EngineProtocol.serialize(cmd);
		synchronized (this) {
			writer.write(json);
			writer.newLine();
			writer.flush();
			while (true) {
				String responseLine = reader.readLine();
				if (responseLine == null) {
					running = false;
					throw new IOException("Engine process closed connection");
				}
				Response resp = EngineProtocol.deserialize(responseLine);
				if (resp.isProgress()) {
					if (onProgress != null) {
						onProgress.accept(resp);
					}
					continue;
				}
				return resp;
			}
		}
	}

	public void dispose() {
		stop();
		executor.shutdownNow();
	}

	private void closeStreams() {
		try {
			if (writer != null) writer.close();
		}
		catch (IOException ignored) {}
		try {
			if (reader != null) reader.close();
		}
		catch (IOException ignored) {}
		writer = null;
		reader = null;
	}

	private void startLogReader(InputStream errorStream) {
		Thread logThread = new Thread(() -> {
			try (BufferedReader br = new BufferedReader(
					new InputStreamReader(errorStream, StandardCharsets.UTF_8))) {
				String line;
				while ((line = br.readLine()) != null) {
					Msg.info(this, "[vulnhunter] " + line);
				}
			}
			catch (IOException e) {
				if (running) {
					Msg.warn(this, "Engine stderr reader stopped", e);
				}
			}
		}, "VulnHunter4Ghidra-LogReader");
		logThread.setDaemon(true);
		logThread.start();
	}

	private String findPython() {
		String envPython = System.getenv("VULNHUNTER_PYTHON");
		if (envPython != null && new File(envPython).isFile()) {
			Msg.info(this, "Using VULNHUNTER_PYTHON: " + envPython);
			return envPython;
		}

		try {
			ResourceFile moduleDir = Application.getModuleDataSubDirectory("");
			File extRoot = moduleDir.getParentFile().getFile(false);
			File dir = extRoot;
			for (int i = 0; i < 8 && dir != null; i++) {
				File venvPython = new File(dir, ".venv/bin/python3");
				if (venvPython.isFile()) {
					Msg.info(this, "Using venv Python: " + venvPython.getAbsolutePath());
					return venvPython.getAbsolutePath();
				}
				dir = dir.getParentFile();
			}
		}
		catch (Exception ignored) {
			// fall through
		}

		String[] candidates = { "python3", "python" };
		for (String candidate : candidates) {
			try {
				Process p = new ProcessBuilder(candidate, "--version")
					.redirectErrorStream(true).start();
				if (p.waitFor(5, TimeUnit.SECONDS) && p.exitValue() == 0) {
					return candidate;
				}
			}
			catch (Exception ignored) {
				// try next
			}
		}
		return "python3";
	}

	private String findServerModule() {
		try {
			ResourceFile moduleDir = Application.getModuleDataSubDirectory("");
			File pythonDir = new File(moduleDir.getParentFile().getFile(false), "python");
			if (pythonDir.isDirectory()) {
				return pythonDir.getAbsolutePath();
			}
		}
		catch (Exception e) {
			Msg.warn(this, "Could not locate bundled python modules", e);
		}
		return ".";
	}
}
