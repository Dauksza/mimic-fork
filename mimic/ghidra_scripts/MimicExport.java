// Deep static analysis export for Mimic. Executed by Ghidra analyzeHeadless.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public class MimicExport extends GhidraScript {
    private String json(String value) {
        if (value == null) return "null";
        StringBuilder out = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\': out.append("\\\\"); break;
                case '"': out.append("\\\""); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 32) out.append(String.format("\\u%04x", (int)c));
                    else out.append(c);
            }
        }
        return out.append('"').toString();
    }

    private String limited(String value, int max) {
        if (value == null) return "";
        String clean = value.replace((char)0, ' ').trim();
        if (clean.length() > max) return clean.substring(0, max);
        return clean;
    }

    private BufferedWriter writer(File file) throws Exception {
        File parent = file.getParentFile();
        if (parent != null) parent.mkdirs();
        return new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8));
    }

    private File sidecar(File report, String suffix) {
        String name = report.getName();
        if (name.toLowerCase().endsWith(".json")) name = name.substring(0, name.length() - 5);
        return new File(report.getParentFile(), name + "." + suffix + ".jsonl");
    }

    private String functionRecord(Function f) {
        StringBuilder b = new StringBuilder("{");
        b.append("\"name\":").append(json(limited(f.getName(), 180)));
        b.append(",\"address\":").append(json(f.getEntryPoint().toString()));
        b.append(",\"namespace\":").append(json(limited(f.getParentNamespace().getName(), 160)));
        b.append(",\"parameter_count\":").append(f.getParameterCount());
        b.append(",\"return_type\":").append(json(limited(f.getReturnType().getDisplayName(), 160)));
        b.append(",\"external\":").append(f.isExternal());
        b.append(",\"thunk\":").append(f.isThunk());
        b.append(",\"size_bytes\":").append(f.getBody().getNumAddresses());
        return b.append("}").toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("MimicExport.java requires an output JSON path.");
            return;
        }
        File output = new File(args[0]).getAbsoluteFile();
        int maxDecompile = 250;
        int perFunctionTimeout = 12;
        if (args.length > 1) {
            try { maxDecompile = Math.max(0, Math.min(5000, Integer.parseInt(args[1]))); }
            catch (Exception ignored) { }
        }
        if (args.length > 2) {
            try { perFunctionTimeout = Math.max(1, Math.min(60, Integer.parseInt(args[2]))); }
            catch (Exception ignored) { }
        }
        File functionsFile = sidecar(output, "functions");
        File symbolsFile = sidecar(output, "symbols");
        File stringsFile = sidecar(output, "strings");
        File callsFile = sidecar(output, "calls");
        File referencesFile = sidecar(output, "references");
        File decompiledFile = sidecar(output, "decompiled");
        List<Function> allFunctions = new ArrayList<Function>();
        List<Function> summaryFunctions = new ArrayList<Function>();
        int functionCount = 0;

        try (BufferedWriter fw = writer(functionsFile)) {
            FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
            while (iterator.hasNext()) {
                Function function = iterator.next();
                functionCount++;
                fw.write(functionRecord(function));
                fw.newLine();
                if (!function.isExternal() && !function.isThunk()) allFunctions.add(function);
                if (summaryFunctions.size() < 350) summaryFunctions.add(function);
                if (functionCount % 1000 == 0) monitor.checkCancelled();
            }
        }

        final Comparator<Function> priority = new Comparator<Function>() {
            public int compare(Function a, Function b) {
                boolean aAuto = a.getName().startsWith("FUN_") || a.getName().startsWith("LAB_");
                boolean bAuto = b.getName().startsWith("FUN_") || b.getName().startsWith("LAB_");
                if (aAuto != bAuto) return aAuto ? 1 : -1;
                long sizeA = a.getBody().getNumAddresses();
                long sizeB = b.getBody().getNumAddresses();
                if (sizeA != sizeB) return sizeA > sizeB ? -1 : 1;
                return a.getName().compareToIgnoreCase(b.getName());
            }
        };
        Collections.sort(allFunctions, priority);

        int symbolCount = 0;
        int externalSymbolCount = 0;
        try (BufferedWriter sw = writer(symbolsFile)) {
            SymbolIterator iterator = currentProgram.getSymbolTable().getAllSymbols(true);
            while (iterator.hasNext()) {
                Symbol symbol = iterator.next();
                StringBuilder item = new StringBuilder("{");
                item.append("\"name\":").append(json(limited(symbol.getName(), 180)));
                item.append(",\"address\":").append(json(symbol.getAddress().toString()));
                item.append(",\"type\":").append(json(symbol.getSymbolType().toString()));
                item.append(",\"namespace\":").append(json(limited(symbol.getParentNamespace().getName(), 160)));
                item.append(",\"external\":").append(symbol.isExternal());
                item.append(",\"primary\":").append(symbol.isPrimary()).append("}");
                sw.write(item.toString());
                sw.newLine();
                symbolCount++;
                if (symbol.isExternal()) externalSymbolCount++;
                if (symbolCount % 10000 == 0) monitor.checkCancelled();
                if (symbolCount >= 250000) break;
            }
        }

        int stringCount = 0;
        try (BufferedWriter stw = writer(stringsFile)) {
            DataIterator iterator = currentProgram.getListing().getDefinedData(true);
            while (iterator.hasNext()) {
                Data data = iterator.next();
                Object value;
                try { value = data.getValue(); }
                catch (Exception ignored) { continue; }
                if (!(value instanceof String)) continue;
                String text = limited((String)value, 2000);
                if (text.length() < 3) continue;
                boolean printable = true;
                for (int i = 0; i < text.length(); i++) {
                    char c = text.charAt(i);
                    if (Character.isISOControl(c) && c != '\t') { printable = false; break; }
                }
                if (!printable) continue;
                stw.write("{\"address\":" + json(data.getAddress().toString()) + ",\"value\":" + json(text) + "}");
                stw.newLine();
                stringCount++;
                if (stringCount % 10000 == 0) monitor.checkCancelled();
                if (stringCount >= 100000) break;
            }
        }

        int referenceCount = 0;
        int callCount = 0;
        try (BufferedWriter cw = writer(callsFile);
             BufferedWriter rw = writer(referencesFile)) {
            for (Function function : allFunctions) {
                InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
                while (instructions.hasNext()) {
                    Instruction instruction = instructions.next();
                    Reference[] references = instruction.getReferencesFrom();
                    for (Reference reference : references) {
                        if (reference == null) continue;
                        Address target = reference.getToAddress();
                        Function destination = currentProgram.getFunctionManager().getFunctionContaining(target);
                        String destinationName = destination == null ? "" : destination.getName();
                        String sourceName = function.getName();
                        String line = "{\"source_function\":" + json(limited(sourceName, 180))
                            + ",\"source_address\":" + json(instruction.getAddress().toString())
                            + ",\"target_address\":" + json(target.toString())
                            + ",\"target_function\":" + json(limited(destinationName, 180))
                            + ",\"reference_type\":" + json(reference.getReferenceType().toString())
                            + ",\"is_call\":" + reference.getReferenceType().isCall() + "}";
                        rw.write(line);
                        rw.newLine();
                        referenceCount++;
                        if (reference.getReferenceType().isCall()) {
                            cw.write(line);
                            cw.newLine();
                            callCount++;
                        }
                        if (referenceCount >= 500000) break;
                    }
                    if (referenceCount >= 500000) break;
                }
                if (referenceCount >= 500000) break;
                if (referenceCount > 0 && referenceCount % 5000 == 0) monitor.checkCancelled();
            }
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        int decompiledCount = 0;
        try (BufferedWriter dw = writer(decompiledFile)) {
            for (Function function : allFunctions) {
                if (decompiledCount >= maxDecompile) break;
                monitor.checkCancelled();
                try {
                    DecompileResults result = decompiler.decompileFunction(function, perFunctionTimeout, monitor);
                    if (!result.decompileCompleted() || result.getDecompiledFunction() == null) continue;
                    String code = limited(result.getDecompiledFunction().getC(), 24000);
                    if (code.length() < 20) continue;
                    String entry = "{\"name\":" + json(limited(function.getName(), 180))
                        + ",\"address\":" + json(function.getEntryPoint().toString())
                        + ",\"code\":" + json(code) + "}";
                    dw.write(entry);
                    dw.newLine();
                    decompiledCount++;
                } catch (Exception ignored) {
                    // Skip individual functions that fail to decompile; preserve other results.
                }
            }
        } finally {
            decompiler.dispose();
        }

        StringBuilder result = new StringBuilder(220000);
        result.append("{\n");
        result.append("\"program_name\":").append(json(currentProgram.getName())).append(",\n");
        result.append("\"language\":").append(json(currentProgram.getLanguage().getLanguageID().getIdAsString())).append(",\n");
        result.append("\"compiler\":").append(json(currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString())).append(",\n");
        result.append("\"image_base\":").append(json(currentProgram.getImageBase().toString())).append(",\n");
        result.append("\"executable_path\":").append(json(currentProgram.getExecutablePath())).append(",\n");
        result.append("\"function_count\":").append(functionCount).append(",\n");
        result.append("\"symbol_count\":").append(symbolCount).append(",\n");
        result.append("\"external_symbol_count\":").append(externalSymbolCount).append(",\n");
        result.append("\"string_count\":").append(stringCount).append(",\n");
        result.append("\"reference_count\":").append(referenceCount).append(",\n");
        result.append("\"call_reference_count\":").append(callCount).append(",\n");
        result.append("\"decompiled_function_count\":").append(decompiledCount).append(",\n");
        result.append("\"exports\":[\n");
        boolean first = true;
        for (Function function : summaryFunctions) {
            if (function.isExternal()) {
                if (!first) result.append(",\n");
                first = false;
                result.append(functionRecord(function));
            }
        }
        result.append("\n],\n\"functions\":[\n");
        first = true;
        for (Function function : summaryFunctions) {
            if (!first) result.append(",\n");
            first = false;
            result.append(functionRecord(function));
        }
        result.append("\n],\n\"symbols\":[\n");
        try (java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(
                 new java.io.FileInputStream(symbolsFile), StandardCharsets.UTF_8))) {
            String line;
            int count = 0;
            while ((line = reader.readLine()) != null && count < 350) {
                if (count > 0) result.append(",\n");
                result.append(line);
                count++;
            }
        }
        result.append("\n],\n\"strings\":[\n");
        try (java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(
                 new java.io.FileInputStream(stringsFile), StandardCharsets.UTF_8))) {
            String line;
            int count = 0;
            while ((line = reader.readLine()) != null && count < 450) {
                if (count > 0) result.append(",\n");
                result.append(line);
                count++;
            }
        }
        result.append("\n],\n\"decompiled_functions\":[\n");
        try (java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(
                 new java.io.FileInputStream(decompiledFile), StandardCharsets.UTF_8))) {
            String line;
            int count = 0;
            while ((line = reader.readLine()) != null && count < 32) {
                if (count > 0) result.append(",\n");
                result.append(line);
                count++;
            }
        }
        result.append("\n],\n");
        result.append("\"sidecars\":{");
        result.append("\"functions\":").append(json(functionsFile.getAbsolutePath())).append(",");
        result.append("\"symbols\":").append(json(symbolsFile.getAbsolutePath())).append(",");
        result.append("\"strings\":").append(json(stringsFile.getAbsolutePath())).append(",");
        result.append("\"calls\":").append(json(callsFile.getAbsolutePath())).append(",");
        result.append("\"references\":").append(json(referencesFile.getAbsolutePath())).append(",");
        result.append("\"decompiled_functions\":").append(json(decompiledFile.getAbsolutePath()));
        result.append("},\n");
        result.append("\"analysis_note\":").append(json("Ghidra auto-analysis plus full inventories and selected function decompilation. Full inventories are stored as local JSONL sidecars.")).append("\n");
        result.append("}\n");
        try (BufferedWriter writer = writer(output)) {
            writer.write(result.toString());
        }
        println("Mimic Ghidra export complete: " + output);
        println("Functions: " + functionCount + "; symbols: " + symbolCount + "; strings: " + stringCount
            + "; calls: " + callCount + "; references: " + referenceCount + "; decompiled: " + decompiledCount);
    }
}
