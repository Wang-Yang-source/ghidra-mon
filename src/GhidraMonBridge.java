// A minimal TCP bridge for Ghidra-Mon
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonArray;

public class GhidraMonBridge extends GhidraScript {
    @Override
    public void run() throws Exception {
        int port = 0; // Find an open port
        ServerSocket serverSocket = new ServerSocket(port);
        port = serverSocket.getLocalPort();
        Gson gson = new Gson();

        // Let the daemon know we are ready and on which port
        println("---GHIDRA_MON_START---");
        JsonObject readyMsg = new JsonObject();
        readyMsg.addProperty("status", "ready");
        readyMsg.addProperty("port", port);
        println(gson.toJson(readyMsg));
        println("---GHIDRA_MON_END---");

        boolean running = true;
        while (running) {
            try {
                Socket client = serverSocket.accept();
                try (
                    BufferedReader in = new BufferedReader(new InputStreamReader(client.getInputStream()));
                    PrintWriter out = new PrintWriter(new OutputStreamWriter(client.getOutputStream()), true)
                ) {
                    String line;
                    while ((line = in.readLine()) != null) {
                        line = line.trim();
                        if (line.isEmpty()) continue;

                        try {
                            JsonObject req = JsonParser.parseString(line).getAsJsonObject();
                            String cmd = req.has("command") ? req.get("command").getAsString() : "";
                            JsonObject args = req.has("args") && !req.get("args").isJsonNull() ? req.getAsJsonObject("args") : new JsonObject();
                            
                            JsonObject resp = new JsonObject();
                            if ("shutdown".equals(cmd)) {
                                resp.addProperty("status", "shutdown");
                                running = false;
                            } else if ("ping".equals(cmd)) {
                                resp.addProperty("status", "ok");
                            } else if ("list_functions".equals(cmd)) {
                                JsonArray funcs = new JsonArray();
                                FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
                                while (iter.hasNext() && funcs.size() < 1000) {
                                    Function f = iter.next();
                                    JsonObject fObj = new JsonObject();
                                    fObj.addProperty("name", f.getName());
                                    fObj.addProperty("address", f.getEntryPoint().toString());
                                    funcs.add(fObj);
                                }
                                resp.add("functions", funcs);
                                resp.addProperty("status", "ok");
                            } else if ("decompile".equals(cmd)) {
                                String targetFunc = args.has("function") ? args.get("function").getAsString() : "";
                                Function f = null;
                                FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
                                while (iter.hasNext()) {
                                    Function func = iter.next();
                                    if (func.getName().equals(targetFunc)) {
                                        f = func;
                                        break;
                                    }
                                }
                                if (f != null) {
                                    DecompInterface decomp = new DecompInterface();
                                    decomp.openProgram(currentProgram);
                                    DecompileResults res = decomp.decompileFunction(f, 30, getMonitor());
                                    if (res.decompileCompleted()) {
                                        resp.addProperty("c_code", res.getDecompiledFunction().getC());
                                        resp.addProperty("status", "ok");
                                    } else {
                                        resp.addProperty("error", "Decompilation failed");
                                    }
                                } else {
                                    resp.addProperty("error", "Function not found");
                                }
                            } else {
                                resp.addProperty("error", "Unknown command: " + cmd);
                            }

                            out.println(gson.toJson(resp));
                            out.flush();

                            if (!running) break;
                        } catch (Exception e) {
                            JsonObject err = new JsonObject();
                            err.addProperty("error", e.getMessage());
                            out.println(gson.toJson(err));
                            out.flush();
                        }
                    }
                }
            } catch (Exception e) {
                // Ignore accept errors
            }
        }
        serverSocket.close();
    }
}
