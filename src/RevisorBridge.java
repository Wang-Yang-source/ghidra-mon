// RevisorBridge - Comprehensive TCP bridge for Revisor
// Provides ~25 commands for full Ghidra programmatic access from Rust/AI agents.
//
// Architecture: Runs as a GhidraScript inside the Ghidra JVM. Opens a TCP
// ServerSocket and accepts JSON-line commands, returning JSON responses.
// Write operations are wrapped in Ghidra transactions for safety.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.block.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Language;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.*;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonArray;

public class RevisorBridge extends GhidraScript {

    private static final int MAX_RESULTS = 5000;
    private Gson gson;

    @Override
    public void run() throws Exception {
        gson = new Gson();
        int port = 0;
        ServerSocket serverSocket = new ServerSocket(port);
        port = serverSocket.getLocalPort();

        // Readiness notification protocol
        println("---REVISOR_START---");
        JsonObject readyMsg = new JsonObject();
        readyMsg.addProperty("status", "ready");
        readyMsg.addProperty("port", port);
        readyMsg.addProperty("program", currentProgram.getName());
        readyMsg.addProperty("language", currentProgram.getLanguageID().toString());
        println(gson.toJson(readyMsg));
        println("---REVISOR_END---");

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

                        JsonObject resp;
                        try {
                            JsonObject req = JsonParser.parseString(line).getAsJsonObject();
                            String cmd = req.has("command") ? req.get("command").getAsString() : "";
                            JsonObject args = req.has("args") && !req.get("args").isJsonNull()
                                ? req.getAsJsonObject("args") : new JsonObject();

                            resp = dispatch(cmd, args);
                            if ("shutdown".equals(cmd)) {
                                running = false;
                            }
                        } catch (Exception e) {
                            resp = errorResponse("Request parse error: " + e.getMessage());
                        }

                        out.println(gson.toJson(resp));
                        out.flush();
                        if (!running) break;
                    }
                }
            } catch (Exception e) {
                // Ignore accept-level errors, keep serving
            }
        }
        serverSocket.close();
    }

    // ─── Command Dispatcher ──────────────────────────────────────────────

    private JsonObject dispatch(String cmd, JsonObject args) {
        try {
            switch (cmd) {
                // ── Lifecycle ──
                case "ping":              return cmdPing();
                case "shutdown":          return cmdShutdown();
                case "program_info":      return cmdProgramInfo();

                // ── Function Queries ──
                case "list_functions":    return cmdListFunctions();
                case "function_at":       return cmdFunctionAt(args);
                case "function_containing": return cmdFunctionContaining(args);
                case "get_function_signature": return cmdGetFunctionSignature(args);
                case "callers":           return cmdCallers(args);
                case "callees":           return cmdCallees(args);

                // ── Decompilation ──
                case "decompile":         return cmdDecompile(args);

                // ── Disassembly ──
                case "instructions_for_function": return cmdInstructionsForFunction(args);
                case "instruction_at":    return cmdInstructionAt(args);

                // ── Memory ──
                case "memory_blocks":     return cmdMemoryBlocks();

                // ── Data & Types ──
                case "data_at":           return cmdDataAt(args);
                case "list_data_types":   return cmdListDataTypes();

                // ── Symbols ──
                case "symbols":           return cmdSymbols(args);
                case "find_symbols":      return cmdFindSymbols(args);

                // ── References ──
                case "get_xrefs":         return cmdReferencesTo(args); // backwards compat
                case "references_to":     return cmdReferencesTo(args);
                case "references_from":   return cmdReferencesFrom(args);

                // ── Strings ──
                case "search_strings":    return cmdSearchStrings(args);

                // ── Graphs ──
                case "call_graph":        return cmdCallGraph(args);
                case "control_flow_graph": return cmdControlFlowGraph(args);

                // ── Import/Export ──
                case "list_imports":      return cmdListImports();
                case "list_exports":      return cmdListExports();

                // ── Write Operations ──
                case "rename_function":   return cmdRenameFunction(args);
                case "set_comment":       return cmdSetComment(args);
                case "set_plate_comment": return cmdSetPlateComment(args);

                default:
                    return errorResponse("Unknown command: " + cmd);
            }
        } catch (Exception e) {
            return errorResponse(cmd + " failed: " + e.getMessage());
        }
    }

    // ─── Helper Methods ──────────────────────────────────────────────────

    private Function findFunctionByName(String name) {
        FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
        while (iter.hasNext()) {
            Function f = iter.next();
            if (f.getName().equals(name)) return f;
        }
        return null;
    }

    private Function findFunctionByAddress(String addrStr) throws Exception {
        Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
        if (addr == null) return null;
        return currentProgram.getFunctionManager().getFunctionAt(addr);
    }

    private Function findFunctionContaining(String addrStr) throws Exception {
        Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
        if (addr == null) return null;
        return currentProgram.getFunctionManager().getFunctionContaining(addr);
    }

    private Function resolveFunction(JsonObject args) throws Exception {
        if (args.has("function")) {
            String name = args.get("function").getAsString();
            Function f = findFunctionByName(name);
            if (f == null) {
                // Try interpreting as address
                f = findFunctionByAddress(name);
            }
            return f;
        }
        if (args.has("address")) {
            return findFunctionByAddress(args.get("address").getAsString());
        }
        return null;
    }

    private String getStr(JsonObject args, String key) {
        return args.has(key) ? args.get(key).getAsString() : "";
    }

    private int getInt(JsonObject args, String key, int def) {
        return args.has(key) ? args.get(key).getAsInt() : def;
    }

    private JsonObject okResponse() {
        JsonObject r = new JsonObject();
        r.addProperty("status", "ok");
        return r;
    }

    private JsonObject errorResponse(String msg) {
        JsonObject r = new JsonObject();
        r.addProperty("status", "error");
        r.addProperty("error", msg);
        return r;
    }

    private JsonObject functionToJson(Function f) {
        JsonObject obj = new JsonObject();
        obj.addProperty("name", f.getName());
        obj.addProperty("address", f.getEntryPoint().toString());
        try { obj.addProperty("signature", f.getSignature().getPrototypeString()); } catch (Exception e) { obj.addProperty("signature", ""); }
        obj.addProperty("size", f.getBody().getNumAddresses());
        obj.addProperty("is_thunk", f.isThunk());
        obj.addProperty("calling_convention", f.getCallingConventionName());
        return obj;
    }

    // ─── Command Implementations ─────────────────────────────────────────

    private JsonObject cmdPing() {
        JsonObject r = okResponse();
        r.addProperty("program", currentProgram.getName());
        return r;
    }

    private JsonObject cmdShutdown() {
        JsonObject r = new JsonObject();
        r.addProperty("status", "shutdown");
        return r;
    }

    // ── program_info ──
    private JsonObject cmdProgramInfo() {
        JsonObject r = okResponse();
        Program p = currentProgram;
        r.addProperty("name", p.getName());
        r.addProperty("language_id", p.getLanguageID().toString());
        r.addProperty("compiler_spec", p.getCompilerSpec().getCompilerSpecID().toString());
        r.addProperty("executable_path", p.getExecutablePath());
        r.addProperty("image_base", p.getImageBase().toString());
        r.addProperty("creation_date", p.getCreationDate().toString());
        r.addProperty("executable_format", p.getExecutableFormat());

        // Counts
        int funcCount = 0;
        FunctionIterator fi = p.getFunctionManager().getFunctions(true);
        while (fi.hasNext()) { fi.next(); funcCount++; }
        r.addProperty("function_count", funcCount);

        int symCount = 0;
        SymbolIterator si = p.getSymbolTable().getAllSymbols(true);
        while (si.hasNext()) { si.next(); symCount++; if (symCount >= MAX_RESULTS) break; }
        r.addProperty("symbol_count", symCount);

        // Address ranges
        JsonArray ranges = new JsonArray();
        for (MemoryBlock block : p.getMemory().getBlocks()) {
            JsonObject b = new JsonObject();
            b.addProperty("name", block.getName());
            b.addProperty("start", block.getStart().toString());
            b.addProperty("end", block.getEnd().toString());
            ranges.add(b);
        }
        r.add("address_ranges", ranges);
        return r;
    }

    // ── list_functions ── (enhanced with more fields)
    private JsonObject cmdListFunctions() {
        JsonObject r = okResponse();
        JsonArray funcs = new JsonArray();
        FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
        int count = 0;
        while (iter.hasNext() && count < MAX_RESULTS) {
            funcs.add(functionToJson(iter.next()));
            count++;
        }
        r.add("functions", funcs);
        r.addProperty("count", count);
        return r;
    }

    // ── function_at ──
    private JsonObject cmdFunctionAt(JsonObject args) throws Exception {
        String addr = getStr(args, "address");
        Function f = findFunctionByAddress(addr);
        if (f == null) return errorResponse("No function at address: " + addr);
        JsonObject r = okResponse();
        r.add("function", functionToJson(f));
        return r;
    }

    // ── function_containing ──
    private JsonObject cmdFunctionContaining(JsonObject args) throws Exception {
        String addr = getStr(args, "address");
        Function f = findFunctionContaining(addr);
        if (f == null) return errorResponse("No function containing address: " + addr);
        JsonObject r = okResponse();
        r.add("function", functionToJson(f));
        return r;
    }

    // ── get_function_signature ──
    private JsonObject cmdGetFunctionSignature(JsonObject args) throws Exception {
        Function f = resolveFunction(args);
        if (f == null) return errorResponse("Function not found");
        JsonObject r = okResponse();
        r.addProperty("name", f.getName());
        r.addProperty("signature", f.getSignature().getPrototypeString());
        r.addProperty("return_type", f.getReturnType().getName());
        r.addProperty("parameter_count", f.getParameterCount());
        JsonArray params = new JsonArray();
        for (var param : f.getParameters()) {
            JsonObject po = new JsonObject();
            po.addProperty("name", param.getName());
            po.addProperty("type", param.getDataType().getName());
            po.addProperty("ordinal", param.getOrdinal());
            params.add(po);
        }
        r.add("parameters", params);
        return r;
    }

    // ── callers ──
    private JsonObject cmdCallers(JsonObject args) throws Exception {
        Function f = resolveFunction(args);
        if (f == null) return errorResponse("Function not found");
        JsonObject r = okResponse();
        JsonArray callers = new JsonArray();
        Set<String> seen = new HashSet<>();
        ReferenceIterator refIter = currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
        int count = 0;
        while (refIter.hasNext() && count < MAX_RESULTS) {
            Reference ref = refIter.next();
            Function caller = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
            if (caller != null && seen.add(caller.getName())) {
                callers.add(functionToJson(caller));
                count++;
            }
        }
        r.add("callers", callers);
        r.addProperty("count", count);
        return r;
    }

    // ── callees ──
    private JsonObject cmdCallees(JsonObject args) throws Exception {
        Function f = resolveFunction(args);
        if (f == null) return errorResponse("Function not found");
        JsonObject r = okResponse();
        JsonArray callees = new JsonArray();
        Set<String> seen = new HashSet<>();
        AddressSetView body = f.getBody();
        InstructionIterator instrIter = currentProgram.getListing().getInstructions(body, true);
        int count = 0;
        while (instrIter.hasNext() && count < MAX_RESULTS) {
            Instruction instr = instrIter.next();
            for (Reference ref : instr.getReferencesFrom()) {
                if (ref.getReferenceType().isCall()) {
                    Function callee = currentProgram.getFunctionManager().getFunctionAt(ref.getToAddress());
                    if (callee != null && seen.add(callee.getName())) {
                        callees.add(functionToJson(callee));
                        count++;
                    }
                }
            }
        }
        r.add("callees", callees);
        r.addProperty("count", count);
        return r;
    }

    // ── decompile ──
    private JsonObject cmdDecompile(JsonObject args) throws Exception {
        Function f = resolveFunction(args);
        if (f == null) return errorResponse("Function not found");
        int timeout = getInt(args, "timeout", 60);
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        try {
            DecompileResults res = decomp.decompileFunction(f, timeout, getMonitor());
            if (res.decompileCompleted()) {
                JsonObject r = okResponse();
                r.addProperty("function_name", f.getName());
                r.addProperty("address", f.getEntryPoint().toString());
                r.addProperty("c_code", res.getDecompiledFunction().getC());
                r.addProperty("signature", res.getDecompiledFunction().getSignature());
                return r;
            } else {
                return errorResponse("Decompilation failed for: " + f.getName());
            }
        } finally {
            decomp.dispose();
        }
    }

    // ── instructions_for_function ──
    private JsonObject cmdInstructionsForFunction(JsonObject args) throws Exception {
        Function f = resolveFunction(args);
        if (f == null) return errorResponse("Function not found");
        JsonObject r = okResponse();
        JsonArray instrs = new JsonArray();
        InstructionIterator iter = currentProgram.getListing().getInstructions(f.getBody(), true);
        int count = 0;
        while (iter.hasNext() && count < MAX_RESULTS) {
            Instruction instr = iter.next();
            JsonObject io = new JsonObject();
            io.addProperty("address", instr.getAddress().toString());
            io.addProperty("mnemonic", instr.getMnemonicString());
            StringBuilder ops = new StringBuilder();
            for (int i = 0; i < instr.getNumOperands(); i++) {
                if (i > 0) ops.append(", ");
                ops.append(instr.getDefaultOperandRepresentation(i));
            }
            io.addProperty("operands", ops.toString());
            io.addProperty("bytes", bytesToHex(instr.getBytes()));
            instrs.add(io);
            count++;
        }
        r.add("instructions", instrs);
        r.addProperty("function_name", f.getName());
        r.addProperty("count", count);
        return r;
    }

    // ── instruction_at ──
    private JsonObject cmdInstructionAt(JsonObject args) throws Exception {
        String addrStr = getStr(args, "address");
        Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
        if (addr == null) return errorResponse("Invalid address: " + addrStr);
        Instruction instr = currentProgram.getListing().getInstructionAt(addr);
        if (instr == null) return errorResponse("No instruction at: " + addrStr);
        JsonObject r = okResponse();
        r.addProperty("address", instr.getAddress().toString());
        r.addProperty("mnemonic", instr.getMnemonicString());
        StringBuilder ops = new StringBuilder();
        for (int i = 0; i < instr.getNumOperands(); i++) {
            if (i > 0) ops.append(", ");
            ops.append(instr.getDefaultOperandRepresentation(i));
        }
        r.addProperty("operands", ops.toString());
        r.addProperty("bytes", bytesToHex(instr.getBytes()));
        return r;
    }

    // ── memory_blocks ──
    private JsonObject cmdMemoryBlocks() {
        JsonObject r = okResponse();
        JsonArray blocks = new JsonArray();
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            JsonObject b = new JsonObject();
            b.addProperty("name", block.getName());
            b.addProperty("start", block.getStart().toString());
            b.addProperty("end", block.getEnd().toString());
            b.addProperty("size", block.getSize());
            b.addProperty("readable", block.isRead());
            b.addProperty("writable", block.isWrite());
            b.addProperty("executable", block.isExecute());
            b.addProperty("initialized", block.isInitialized());
            b.addProperty("type", block.getType().toString());
            blocks.add(b);
        }
        r.add("blocks", blocks);
        return r;
    }

    // ── data_at ──
    private JsonObject cmdDataAt(JsonObject args) throws Exception {
        String addrStr = getStr(args, "address");
        Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
        if (addr == null) return errorResponse("Invalid address: " + addrStr);
        Data data = currentProgram.getListing().getDataAt(addr);
        if (data == null) return errorResponse("No data at: " + addrStr);
        JsonObject r = okResponse();
        r.addProperty("address", data.getAddress().toString());
        r.addProperty("data_type", data.getDataType().getName());
        r.addProperty("size", data.getLength());
        try {
            Object val = data.getValue();
            r.addProperty("value", val != null ? val.toString() : "null");
        } catch (Exception e) {
            r.addProperty("value", "");
        }
        return r;
    }

    // ── list_data_types ──
    private JsonObject cmdListDataTypes() {
        JsonObject r = okResponse();
        JsonArray types = new JsonArray();
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        Iterator<DataType> iter = dtm.getAllDataTypes();
        int count = 0;
        while (iter.hasNext() && count < MAX_RESULTS) {
            DataType dt = iter.next();
            JsonObject obj = new JsonObject();
            obj.addProperty("name", dt.getName());
            obj.addProperty("category", dt.getCategoryPath().toString());
            obj.addProperty("size", dt.getLength());
            obj.addProperty("description", dt.getDescription() != null ? dt.getDescription() : "");
            types.add(obj);
            count++;
        }
        r.add("data_types", types);
        r.addProperty("count", count);
        return r;
    }

    // ── symbols ──
    private JsonObject cmdSymbols(JsonObject args) {
        JsonObject r = okResponse();
        JsonArray syms = new JsonArray();
        String filterType = getStr(args, "type");
        SymbolIterator iter = currentProgram.getSymbolTable().getAllSymbols(true);
        int count = 0;
        while (iter.hasNext() && count < MAX_RESULTS) {
            Symbol sym = iter.next();
            if (!filterType.isEmpty() && !sym.getSymbolType().toString().equalsIgnoreCase(filterType)) {
                continue;
            }
            JsonObject so = new JsonObject();
            so.addProperty("name", sym.getName());
            so.addProperty("address", sym.getAddress().toString());
            so.addProperty("symbol_type", sym.getSymbolType().toString());
            so.addProperty("namespace", sym.getParentNamespace().getName());
            so.addProperty("is_primary", sym.isPrimary());
            syms.add(so);
            count++;
        }
        r.add("symbols", syms);
        r.addProperty("count", count);
        return r;
    }

    // ── find_symbols ──
    private JsonObject cmdFindSymbols(JsonObject args) {
        String query = getStr(args, "query").toLowerCase();
        JsonObject r = okResponse();
        JsonArray syms = new JsonArray();
        SymbolIterator iter = currentProgram.getSymbolTable().getAllSymbols(true);
        int count = 0;
        while (iter.hasNext() && count < MAX_RESULTS) {
            Symbol sym = iter.next();
            if (sym.getName().toLowerCase().contains(query)) {
                JsonObject so = new JsonObject();
                so.addProperty("name", sym.getName());
                so.addProperty("address", sym.getAddress().toString());
                so.addProperty("symbol_type", sym.getSymbolType().toString());
                so.addProperty("namespace", sym.getParentNamespace().getName());
                syms.add(so);
                count++;
            }
        }
        r.add("symbols", syms);
        r.addProperty("count", count);
        return r;
    }

    // ── references_to (also handles get_xrefs for backwards compat) ──
    private JsonObject cmdReferencesTo(JsonObject args) throws Exception {
        // Support both function-name and address-based lookup
        Address targetAddr = null;
        if (args.has("function")) {
            Function f = resolveFunction(args);
            if (f == null) return errorResponse("Function not found");
            targetAddr = f.getEntryPoint();
        } else if (args.has("address")) {
            targetAddr = currentProgram.getAddressFactory().getAddress(getStr(args, "address"));
        }
        if (targetAddr == null) return errorResponse("No target specified (use 'function' or 'address')");

        JsonObject r = okResponse();
        JsonArray refs = new JsonArray();
        ReferenceIterator refIter = currentProgram.getReferenceManager().getReferencesTo(targetAddr);
        int count = 0;
        while (refIter.hasNext() && count < MAX_RESULTS) {
            Reference ref = refIter.next();
            JsonObject ro = new JsonObject();
            ro.addProperty("from_address", ref.getFromAddress().toString());
            ro.addProperty("to_address", ref.getToAddress().toString());
            ro.addProperty("ref_type", ref.getReferenceType().getName());
            ro.addProperty("is_call", ref.getReferenceType().isCall());
            // Also include the containing function name for convenience
            Function fromFunc = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
            ro.addProperty("from_function", fromFunc != null ? fromFunc.getName() : "");
            refs.add(ro);
            count++;
        }
        r.add("xrefs", refs); // keep "xrefs" key for backwards compat
        r.add("references", refs); // also provide as "references"
        r.addProperty("count", count);
        return r;
    }

    // ── references_from ──
    private JsonObject cmdReferencesFrom(JsonObject args) throws Exception {
        String addrStr = getStr(args, "address");
        Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
        if (addr == null) return errorResponse("Invalid address: " + addrStr);

        JsonObject r = okResponse();
        JsonArray refs = new JsonArray();
        Reference[] fromRefs = currentProgram.getReferenceManager().getReferencesFrom(addr);
        for (Reference ref : fromRefs) {
            JsonObject ro = new JsonObject();
            ro.addProperty("from_address", ref.getFromAddress().toString());
            ro.addProperty("to_address", ref.getToAddress().toString());
            ro.addProperty("ref_type", ref.getReferenceType().getName());
            ro.addProperty("is_call", ref.getReferenceType().isCall());
            Function toFunc = currentProgram.getFunctionManager().getFunctionAt(ref.getToAddress());
            ro.addProperty("to_function", toFunc != null ? toFunc.getName() : "");
            refs.add(ro);
        }
        r.add("references", refs);
        r.addProperty("count", fromRefs.length);
        return r;
    }

    // ── search_strings ──
    private JsonObject cmdSearchStrings(JsonObject args) {
        String search = getStr(args, "query");
        JsonObject r = okResponse();
        JsonArray strings = new JsonArray();
        Listing listing = currentProgram.getListing();
        DataIterator dataIter = listing.getDefinedData(true);
        int count = 0;
        while (dataIter.hasNext() && count < MAX_RESULTS) {
            Data d = dataIter.next();
            if (d.hasStringValue()) {
                String val = (String) d.getValue();
                if (search.isEmpty() || val.contains(search)) {
                    JsonObject sObj = new JsonObject();
                    sObj.addProperty("address", d.getAddress().toString());
                    sObj.addProperty("value", val);
                    sObj.addProperty("length", val.length());
                    sObj.addProperty("data_type", d.getDataType().getName());
                    strings.add(sObj);
                    count++;
                }
            }
        }
        r.add("strings", strings);
        r.addProperty("count", count);
        return r;
    }

    // ── call_graph ──
    private JsonObject cmdCallGraph(JsonObject args) {
        int maxDepth = getInt(args, "depth", 0); // 0 = unlimited
        JsonObject r = okResponse();
        JsonArray nodes = new JsonArray();
        JsonArray edges = new JsonArray();
        Set<String> nodeSet = new HashSet<>();

        FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);
        int funcCount = 0;
        while (funcIter.hasNext() && funcCount < MAX_RESULTS) {
            Function f = funcIter.next();
            String fname = f.getName();
            if (nodeSet.add(fname)) {
                JsonObject node = new JsonObject();
                node.addProperty("name", fname);
                node.addProperty("address", f.getEntryPoint().toString());
                nodes.add(node);
                funcCount++;
            }

            // Find calls from this function
            AddressSetView body = f.getBody();
            InstructionIterator instrIter = currentProgram.getListing().getInstructions(body, true);
            while (instrIter.hasNext()) {
                Instruction instr = instrIter.next();
                for (Reference ref : instr.getReferencesFrom()) {
                    if (ref.getReferenceType().isCall()) {
                        Function callee = currentProgram.getFunctionManager().getFunctionAt(ref.getToAddress());
                        if (callee != null) {
                            JsonObject edge = new JsonObject();
                            edge.addProperty("from_name", fname);
                            edge.addProperty("from_address", f.getEntryPoint().toString());
                            edge.addProperty("to_name", callee.getName());
                            edge.addProperty("to_address", callee.getEntryPoint().toString());
                            edges.add(edge);

                            if (nodeSet.add(callee.getName())) {
                                JsonObject calleeNode = new JsonObject();
                                calleeNode.addProperty("name", callee.getName());
                                calleeNode.addProperty("address", callee.getEntryPoint().toString());
                                nodes.add(calleeNode);
                            }
                        }
                    }
                }
            }
        }
        r.add("nodes", nodes);
        r.add("edges", edges);
        r.addProperty("node_count", nodes.size());
        r.addProperty("edge_count", edges.size());
        return r;
    }

    // ── control_flow_graph ──
    private JsonObject cmdControlFlowGraph(JsonObject args) throws Exception {
        Function f = resolveFunction(args);
        if (f == null) return errorResponse("Function not found");

        JsonObject r = okResponse();
        r.addProperty("function_name", f.getName());

        BasicBlockModel bbModel = new BasicBlockModel(currentProgram);
        CodeBlockIterator blockIter = bbModel.getCodeBlocksContaining(f.getBody(), getMonitor());

        JsonArray blocks = new JsonArray();
        JsonArray edges = new JsonArray();
        Map<String, Integer> blockIndex = new HashMap<>();
        int idx = 0;

        while (blockIter.hasNext()) {
            CodeBlock block = blockIter.next();
            String startAddr = block.getFirstStartAddress().toString();
            blockIndex.put(startAddr, idx);

            JsonObject bo = new JsonObject();
            bo.addProperty("id", idx);
            bo.addProperty("start_address", startAddr);
            bo.addProperty("end_address", block.getMaxAddress().toString());

            // Instructions in this block
            JsonArray instrs = new JsonArray();
            InstructionIterator instrIter = currentProgram.getListing().getInstructions(block, true);
            while (instrIter.hasNext()) {
                Instruction instr = instrIter.next();
                JsonObject io = new JsonObject();
                io.addProperty("address", instr.getAddress().toString());
                io.addProperty("mnemonic", instr.getMnemonicString());
                StringBuilder ops = new StringBuilder();
                for (int i = 0; i < instr.getNumOperands(); i++) {
                    if (i > 0) ops.append(", ");
                    ops.append(instr.getDefaultOperandRepresentation(i));
                }
                io.addProperty("operands", ops.toString());
                instrs.add(io);
            }
            bo.add("instructions", instrs);
            blocks.add(bo);
            idx++;
        }

        // Build edges (destinations of each block)
        blockIter = bbModel.getCodeBlocksContaining(f.getBody(), getMonitor());
        while (blockIter.hasNext()) {
            CodeBlock block = blockIter.next();
            String fromAddr = block.getFirstStartAddress().toString();
            Integer fromIdx = blockIndex.get(fromAddr);
            if (fromIdx == null) continue;

            CodeBlockReferenceIterator destIter = block.getDestinations(getMonitor());
            while (destIter.hasNext()) {
                CodeBlockReference destRef = destIter.next();
                String toAddr = destRef.getDestinationAddress().toString();
                Integer toIdx = blockIndex.get(toAddr);

                JsonObject edge = new JsonObject();
                edge.addProperty("from_block", fromIdx);
                edge.addProperty("from_address", fromAddr);
                edge.addProperty("to_address", toAddr);
                edge.addProperty("to_block", toIdx != null ? toIdx : -1);
                edge.addProperty("edge_type", destRef.getFlowType().toString());
                edges.add(edge);
            }
        }

        r.add("blocks", blocks);
        r.add("edges", edges);
        r.addProperty("block_count", blocks.size());
        r.addProperty("edge_count", edges.size());
        return r;
    }

    // ── list_imports ──
    private JsonObject cmdListImports() {
        JsonObject r = okResponse();
        JsonArray imports = new JsonArray();
        SymbolTable symTable = currentProgram.getSymbolTable();
        SymbolIterator iter = symTable.getExternalSymbols();
        int count = 0;
        while (iter.hasNext() && count < MAX_RESULTS) {
            Symbol sym = iter.next();
            JsonObject io = new JsonObject();
            io.addProperty("name", sym.getName());
            io.addProperty("address", sym.getAddress().toString());
            // Get library name from parent namespace
            Namespace ns = sym.getParentNamespace();
            io.addProperty("library", ns != null ? ns.getName() : "");
            io.addProperty("symbol_type", sym.getSymbolType().toString());
            imports.add(io);
            count++;
        }
        r.add("imports", imports);
        r.addProperty("count", count);
        return r;
    }

    // ── list_exports ──
    private JsonObject cmdListExports() {
        JsonObject r = okResponse();
        JsonArray exports = new JsonArray();
        SymbolTable symTable = currentProgram.getSymbolTable();
        AddressIterator addrIter = symTable.getExternalEntryPointIterator();
        int count = 0;
        while (addrIter.hasNext() && count < MAX_RESULTS) {
            Address addr = addrIter.next();
            JsonObject eo = new JsonObject();
            eo.addProperty("address", addr.toString());
            Symbol sym = symTable.getPrimarySymbol(addr);
            eo.addProperty("name", sym != null ? sym.getName() : "");
            Function f = currentProgram.getFunctionManager().getFunctionAt(addr);
            if (f != null) {
                eo.addProperty("signature", f.getSignature().getPrototypeString());
            }
            exports.add(eo);
            count++;
        }
        r.add("exports", exports);
        r.addProperty("count", count);
        return r;
    }

    // ── rename_function (write, transactional) ──
    private JsonObject cmdRenameFunction(JsonObject args) throws Exception {
        Function f = resolveFunction(args);
        if (f == null) return errorResponse("Function not found");
        String newName = getStr(args, "new_name");
        if (newName.isEmpty()) return errorResponse("'new_name' is required");

        String oldName = f.getName();
        int txId = currentProgram.startTransaction("Rename " + oldName + " -> " + newName);
        try {
            f.setName(newName, SourceType.USER_DEFINED);
            currentProgram.endTransaction(txId, true);
        } catch (Exception e) {
            currentProgram.endTransaction(txId, false);
            return errorResponse("Rename failed: " + e.getMessage());
        }

        JsonObject r = okResponse();
        r.addProperty("old_name", oldName);
        r.addProperty("new_name", newName);
        r.addProperty("address", f.getEntryPoint().toString());
        return r;
    }

    // ── set_comment (write, transactional) ──
    private JsonObject cmdSetComment(JsonObject args) throws Exception {
        String addrStr = getStr(args, "address");
        Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
        if (addr == null) return errorResponse("Invalid address: " + addrStr);
        String comment = getStr(args, "comment");

        int txId = currentProgram.startTransaction("Set comment at " + addrStr);
        try {
            currentProgram.getListing().setComment(addr, CodeUnit.EOL_COMMENT, comment);
            currentProgram.endTransaction(txId, true);
        } catch (Exception e) {
            currentProgram.endTransaction(txId, false);
            return errorResponse("Set comment failed: " + e.getMessage());
        }

        JsonObject r = okResponse();
        r.addProperty("address", addrStr);
        r.addProperty("comment", comment);
        return r;
    }

    // ── set_plate_comment (write, transactional) ──
    private JsonObject cmdSetPlateComment(JsonObject args) throws Exception {
        Function f = resolveFunction(args);
        if (f == null) return errorResponse("Function not found");
        String comment = getStr(args, "comment");

        int txId = currentProgram.startTransaction("Set plate comment for " + f.getName());
        try {
            f.setComment(comment);
            currentProgram.endTransaction(txId, true);
        } catch (Exception e) {
            currentProgram.endTransaction(txId, false);
            return errorResponse("Set plate comment failed: " + e.getMessage());
        }

        JsonObject r = okResponse();
        r.addProperty("function", f.getName());
        r.addProperty("comment", comment);
        return r;
    }

    // ─── Utilities ───────────────────────────────────────────────────────

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
