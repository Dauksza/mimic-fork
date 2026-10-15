// Ghidra headless export script. Produces local static-analysis evidence for Mimic.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
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
        String clean = value.replace('\u0000', ' ').trim();
        if (clean.length() > max) return clean.substring(0, max);
        return clean;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("MimicExport.java requires an output JSON path.");
            return;
        }
        File output = new File(args[0]).getAbsoluteFile();
        File parent = output.getParentFile();
        if (parent != null) parent.mkdirs();

        List<Function> functions = new ArrayList<>();
        FunctionIterator functionIterator = currentProgram.getFunctionManager().getFunctions(true);
        int functionCount = 0;
        while (functionIterator.hasNext()) {
            Function function = functionIterator.next();
            functionCount++;
            if (functions.size() < 350 && !function.isExternal()) {
                functions.add(function);
            }
            if (functionCount % 500 == 0) monitor.checkCancelled();
        }

        StringBuilder result = new StringBuilder(160000);
        result.append("{\n");
        result.append("\"program_name\":").append(json(currentProgram.getName())).append(",\n");
        result.append("\"language\":").append(json(currentProgram.getLanguage().getLanguageID().getIdAsString())).append(",\n");
        result.append("\"compiler\":").append(json(currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString())).append(",\n");
        result.append("\"image_base\":").append(json(currentProgram.getImageBase().toString())).append(",\n");
        result.append("\"executable_path\":").append(json(currentProgram.getExecutablePath())).append(",\n");
        result.append("\"function_count\":").append(functionCount).append(",\n");
        result.append("\"functions\":[\n");
        for (int i = 0; i < functions.size(); i++) {
            Function f = functions.get(i);
            if (i > 0) result.append(",\n");
            result.append("{\"name\":").append(json(limited(f.getName(), 180)));
            result.append(",\"address\":").append(json(f.getEntryPoint().toString()));
            result.append(",\"parameter_count\":").append(f.getParameterCount());
            result.append(",\"thunk\":").append(f.isThunk());
            try {
                result.append(",\"size_bytes\":").append(f.getBody().getNumAddresses());
            } catch (Exception ignored) {
                result.append(",\"size_bytes\":0");
            }
            result.append("}");
        }
        result.append("\n],\n");

        result.append("\"symbols\":[\n");
        SymbolIterator symbolIterator = currentProgram.getSymbolTable().getAllSymbols(true);
        int symbolCount = 0;
        boolean firstSymbol = true;
        while (symbolIterator.hasNext() && symbolCount < 350) {
            Symbol symbol = symbolIterator.next();
            if (!firstSymbol) result.append(",\n");
            firstSymbol = false;
            result.append("{\"name\":").append(json(limited(symbol.getName(), 160)));
            result.append(",\"address\":").append(json(symbol.getAddress().toString()));
            result.append(",\"type\":").append(json(symbol.getSymbolType().toString())).append("}");
            symbolCount++;
        }
        result.append("\n],\n");

        result.append("\"strings\":[\n");
        DataIterator dataIterator = currentProgram.getListing().getDefinedData(true);
        int stringCount = 0;
        boolean firstString = true;
        while (dataIterator.hasNext() && stringCount < 400) {
            Data data = dataIterator.next();
            Object value;
            try {
                value = data.getValue();
            } catch (Exception ignored) {
                continue;
            }
            if (!(value instanceof String)) continue;
            String text = limited((String)value, 280);
            if (text.length() < 3) continue;
            boolean printable = true;
            for (int i = 0; i < text.length(); i++) {
                char c = text.charAt(i);
                if (Character.isISOControl(c) && c != '\t') { printable = false; break; }
            }
            if (!printable) continue;
            if (!firstString) result.append(",\n");
            firstString = false;
            result.append("{\"address\":").append(json(data.getAddress().toString()));
            result.append(",\"value\":").append(json(text)).append("}");
            stringCount++;
        }
        result.append("\n],\n");

        result.append("\"decompiled_functions\":[\n");
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        int decompiledCount = 0;
        boolean firstDecompiled = true;
        try {
            for (Function f : functions) {
                if (decompiledCount >= 28) break;
                if (f.isThunk() || f.isExternal()) continue;
                String name = f.getName();
                // Preserve useful application logic before compiler-generated helpers.
                if (name.startsWith("FUN_") && decompiledCount >= 12) continue;
                try {
                    DecompileResults decompiled = decompiler.decompileFunction(f, 45, monitor);
                    if (!decompiled.decompileCompleted() || decompiled.getDecompiledFunction() == null) continue;
                    String code = limited(decompiled.getDecompiledFunction().getC(), 5000);
                    if (code.isEmpty()) continue;
                    if (!firstDecompiled) result.append(",\n");
                    firstDecompiled = false;
                    result.append("{\"name\":").append(json(limited(name, 180)));
                    result.append(",\"address\":").append(json(f.getEntryPoint().toString()));
                    result.append(",\"code\":").append(json(code)).append("}");
                    decompiledCount++;
                } catch (Exception ignored) {
                    // A single unsupported or malformed function must not abort the report.
                }
            }
        } finally {
            decompiler.dispose();
        }
        result.append("\n],\n");
        result.append("\"analysis_note\":").append(json("Ghidra static analysis output. Decompiled functions are evidence for authorized analysis, not a guarantee of complete recovered behavior.")).append("\n");
        result.append("}\n");

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(output))) {
            writer.write(result.toString());
        }
        println("Mimic exported Ghidra report: " + output);
        println("Functions: " + functionCount + "; strings: " + stringCount + "; decompiled: " + decompiledCount);
    }
}
