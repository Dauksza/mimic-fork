# mimic — local app capture and reconstruction

Mimic can observe an explicitly selected Windows program, run native Ghidra static analysis on its executable, examine visible UI Automation structures and screenshots, and use local Ollama to generate a native desktop reconstruction, web reconstruction, or Python API client. Use it only on software you own or are authorized to analyze. **All AI generation uses your local Ollama server; there is no cloud AI provider or API key.**

It cannot recover the original private source code. It reconstructs observable behavior from captured network requests, responses, and optional screenshots. Better evidence produces a better result; unobserved screens and workflows remain inferred.

## What it can build today

- **Traffic evidence:** browser HAR files or live mitmproxy capture.
- **Endpoint inventory:** host, method, path, status, request/response examples.
- **Python API client:** generated locally with Ollama.
- **Web app reconstruction:** React/Vite project with navigation, responsive styling, forms, API integration, loading/error/empty states, setup instructions, and a coverage report.
- **Windows desktop capture:** arm the Mimic observer, open the target program, use it, then stop capture. The selected process's visible UI Automation structure and screenshot changes are recorded.
- **Ghidra static reverse engineering:** Mimic invokes the installed Ghidra headless analyzer, exports function names, symbols, strings, and selected decompiled functions, then supplies a sanitized summary to local Ollama.
- **Native Windows UI reconstruction:** generate an editable Python/PySide6 app informed by captured windows, controls, geometry, screenshots, and Ghidra analysis.
- **Visual evidence:** a locally installed vision-capable Ollama model can analyze screenshots to infer layout and styling.
- **Safety checks:** generated paths are validated; captured auth headers are not sent as part of the endpoint digest; common token/password fields in captured bodies are redacted; captured credentials are not exported into generated source.

## Requirements

- Python 3.10+
- [Ollama](https://ollama.com) running locally or on a trusted private LAN
- A coding model installed in Ollama. Recommended starting point:

```powershell
ollama pull qwen2.5-coder:14b
ollama list
```

If using screenshots, select a vision-capable model supported by your Ollama installation. Configure a model with `--model`.

Install the project from a checkout:

```powershell
python -m pip install -e .
```

Optional live traffic capture:

```powershell
python -m pip install -e ".[capture]"
```

For PE metadata extraction during analysis:

```powershell
python -m pip install -e ".[analysis]"
```

## Reverse-engineer app formats with mimic-analyze

Run format-aware static analysis without a desktop capture session:

```powershell
python -m pip install -e ".[analysis]"
mimic-analyze "C:/Program Files/Vendor/App/App.exe" --out ./app-analysis --ghidra-home "C:/Tools/ghidra_PUBLIC" --max-decompile 1000
```

The command classifies the target format, records file hashes and tool availability, stores full tool output locally, and asks local Ollama for an evidence-grounded report. Use --no-summary to collect static artifacts without invoking Ollama.

Ghidra analysis defaults to decompiling up to **1,000 functions per primary binary**. Raise it for deeper analysis or reduce it for quicker first-pass triage:

```powershell
# Deep pass (can take hours on large binaries)
mimic-analyze "C:/Path/App.exe" --out ./deep-analysis --max-decompile 5000

# Inventory-focused pass without decompiling functions
mimic-analyze "C:/Path/App.exe" --out ./inventory --max-decompile 0 --no-summary
```

The cap is per primary binary; package adapters may divide the budget among bundled native modules to avoid spending the entire run on one library. Function inventories, symbols, references, strings, and dependency metadata are collected separately where the binary format and installed tools support them. Increasing the cap does not guarantee full decompilation: stripped, packed, obfuscated, encrypted, or unsupported binaries can still limit results.

Examples:

```powershell
mimic-analyze "C:/Program Files/Vendor/App" --out ./app-analysis --ghidra-home "C:/Tools/ghidra_PUBLIC"
mimic-analyze ./target.apk --out ./apk-analysis --ghidra-home C:/Tools/ghidra_PUBLIC
mimic-analyze ./library.jar --out ./jar-analysis
mimic-analyze ./module.wasm --out ./wasm-analysis
mimic-analyze C:/Path/To/resources/app.asar --out ./electron-analysis
mimic-analyze ./source.zip --out ./source-analysis
```

### Local analyzers by application type

Mimic does not download or install reverse-engineering tools. Install required tools from their official upstream releases and put the needed command-line executable on PATH.

| Target type | Analyzer used when present | Evidence produced |
|---|---|---|
| Windows EXE/DLL/OCX/SYS | Ghidra headless, pefile | functions, selected decompilation, symbols, references/call graph, strings, imports/exports, PE headers/sections and app-local DLLs |
| .NET assemblies and apphost | Ghidra for native wrappers; ilspycmd for managed DLLs when installed | managed source tree, types, runtime configs, dependencies and native imports |
| Android APK/AAB/AAR/APKM/APKS/XAPK | JADX, Apktool, Ghidra for bundled native libraries | decompiled bytecode, manifest/resources/smali, DEX/native inventory |
| JVM JAR/class | JADX and javap from a JDK | decompiled source where supported, bytecode, method descriptors and class inventory |
| Electron | installed asar CLI | extracted JS/HTML/CSS/resources and package metadata |
| Python source, pyz, pyc, frozen PyInstaller | source inventory, matching-version dis; optional pyinstxtractor-ng and decompyle3/uncompyle6 | source structure and bytecode disassembly/decompilation where compatible |
| iOS IPA/macOS app bundle/native frameworks | plist/resource inspection and Ghidra for supported native modules | bundle metadata, native functions and strings |
| Windows MSIX/APPX/MSI/EXE installers | package inspection; optional lessmsi, innoextract or 7-Zip | manifests, files and extracted payload binaries |
| JavaScript/TypeScript/Python/Java/C#/Go/Rust source | source inventory and project metadata | file hashes, class/function names, likely entry-point source excerpts |
| Linux packages (.deb, .rpm, AppImage, Snap, Flatpak) and macOS containers (.dmg, .pkg) | dpkg-deb, unsquashfs, pkgutil, bsdtar or 7-Zip when installed | package payload, manifests/configs and native modules |
| Safe tar archives (.tar, .tar.gz, .tar.bz2, .tar.xz) | Mimic's selective extractor (regular source/config/binary files only; links/special entries are skipped) | source inventory and selected binary analysis |
| WebAssembly .wasm/.wat | wasm-tools, WABT (wasm2wat/wasm-objdump), wasm-decompile | module structure, imports/exports and disassembly/decompilation |

Install only adapters appropriate to your target. For example, ILSpy command-line for .NET:

```powershell
dotnet tool install --global ilspycmd
```

Install JADX and Apktool for Android, Node.js plus the documented asar CLI for Electron, pyinstxtractor-ng and bytecode-version-compatible decompilers for frozen Python, and WABT or wasm-tools for WebAssembly. These are external tools and must be installed locally; Mimic reports when one is missing.

Full reports and JSONL sidecars are kept on disk. Ollama receives a capped evidence set rather than entire binary dumps. Large or packed targets may require more time or specialized handling.

## Reconstruct a Windows desktop program

This workflow is designed for a Windows PC. Install Mimic and the Windows capture dependencies:

```powershell
python -m pip install -e ".[windows]"
ollama pull qwen2.5-coder:14b
ollama pull qwen2.5vl:7b
```

Install Ghidra separately from the official [Ghidra releases](https://github.com/NationalSecurityAgency/ghidra/releases) and extract it. The configured folder must contain Ghidra's headless launcher: `support\\analyzeHeadless.bat` on Windows, or `support/analyzeHeadless` on Linux/macOS. Set `GHIDRA_HOME` to that folder. Windows GUI capture itself remains Windows-only.

Launch Mimic:

```powershell
mimic-desktop
```

1. Click **ARM CAPTURE**.
2. Open the target Windows program after Mimic is armed.
3. Use the application's normal screens, menus, dialogs, settings, and key workflows with data you are authorized to use.
4. Click **STOP CAPTURE**.
5. Click **GENERATE DESKTOP COPY**. Mimic identifies the target format, runs available local analyzers, generates a bounded Ollama analysis report, then uses local Ollama to generate a PySide6 project.

Captures are stored beneath `%USERPROFILE%\\MimicProjects\\Captures`. The generated project defaults to `%USERPROFILE%\\MimicProjects\\Reconstructions`.

Generated app source is not guaranteed to reproduce hidden server behavior or proprietary logic. The Ghidra project and `ghidra-analysis.json` report are kept in the capture's `reverse-engineering` directory so you can inspect the analysis in Ghidra.

### Command-line desktop reconstruction

After capturing a session, Mimic can do the same Ghidra-plus-Ollama pipeline from a terminal:

```powershell
mimic-desktop-build "$env:USERPROFILE\\MimicProjects\\Captures\\YOUR_CAPTURE_FOLDER" --out "$env:USERPROFILE\\MimicProjects\\Reconstructions\\my-clone" --ghidra-home "$env:USERPROFILE\\ghidra_XX_PUBLIC" --model qwen2.5-coder:14b --vision-model qwen2.5vl:7b
cd "$env:USERPROFILE\\MimicProjects\\Reconstructions\\my-clone"
python -m pip install -r requirements.txt
python main.py
```

`--binary C:\\path\\to\\app.exe` can be supplied when the automatic process-to-executable lookup fails. Ghidra must be installed; use `--ghidra-home` to identify its extracted folder.

### What Ghidra contributes

Ghidra imports and analyzes the selected EXE/DLL and exports an inventory of functions, symbols, string constants, and selected decompilation. Mimic gives relevant static-analysis evidence to Ollama alongside captured UI states. This is real static binary analysis, but it cannot guarantee recovery of original source code, runtime-only behavior, server services, encrypted data, or behavior concealed by packers and obfuscation. Generated code is a new reconstruction, not a recovered copy of the original implementation.

### Optional runtime analysis

Mimic can attach a Frida trace to the selected program when you explicitly enable the Advanced runtime trace option before capture. Install the optional dependency:

```powershell
python -m pip install -e ".[instrumentation]"
```

Or trace an authorized running process from the command line:

```powershell
mimic-trace 12345 --out ./runtime-events.jsonl --duration 120
```

The trace records loaded modules and selected file-path, registry-subkey, and network-destination metadata. It does not record global keystrokes, command-line arguments, clipboard content, file contents, or network/request payloads. Instrumentation can affect program stability and does not prove an operation succeeded.

### Windows capture limits and privacy

Capture uses Windows UI Automation and screenshots. Interfaces drawn entirely on a custom canvas, protected processes, remote desktop surfaces, and some GPU-rendered apps may expose little UI structure. Edit/document/password values are omitted from the element tree, and Mimic does not install global keyboard hooks or read the clipboard. Screenshots can still show sensitive information; use a clean test account and keep the capture folder private.

## Reconstruct a web app from a HAR file

1. Open the target app in a browser account you are authorized to use.
2. Open Developer Tools → Network, enable Preserve log, and exercise the key workflows.
3. Export the captured requests as a HAR file. Treat HAR files as sensitive because they can contain session cookies and personal data.
4. Put screenshots of important screens in a folder, if available.
5. Build the reconstruction with local Ollama:

```powershell
mimic-build api.example.com --har .\capture.har --screenshots .\screenshots --name "Target App" --out .\target-app-web
cd .\target-app-web
npm install
npm run dev
```

The `--screenshots` option is optional. If your Ollama server is not on localhost, set `OLLAMA_HOST` or use `--ollama-url http://YOUR-OLLAMA-HOST:11434`. The model must already be downloaded.

To inspect what the HAR contains first:

```powershell
mimic hosts --har .\capture.har
mimic learn api.example.com --har .\capture.har
```

## Live capture

```powershell
mimic record
mimic hosts
mimic learn api.example.com
mimic-build api.example.com --screenshots .\screenshots --out .\target-app-web
```

Use the proxy only with devices and accounts you are authorized to inspect. Certificate-pinning bypasses are not a guarantee and may be unavailable or inappropriate for many apps.

## Generate a Python API client

```powershell
mimic gen api.example.com --har .\capture.har --model qwen2.5-coder:14b
```

This generates a Python client using Ollama only. The existing `mimic.Session` functionality remains available for requests and captured session reuse.

## Configuration

- `OLLAMA_HOST`: Ollama base URL; defaults to `http://127.0.0.1:11434`.
- `MIMIC_OLLAMA_MODEL`: default model; defaults to `qwen2.5-coder:14b`.
- `--model`: choose an installed model per generation command.
- `--ollama-url`: set a server URL for `mimic-build`.

No cloud API key is needed or requested.

## Accuracy and limitations

- A HAR only includes requests made during the captured session. Exercise login, navigation, search, create/edit/delete actions, settings, error cases, and other important flows if you need them reproduced.
- Screenshots improve visual inference but do not reveal hidden interactions by themselves.
- The web generator targets **React/Vite**. The Windows generator creates **native PySide6 desktop UI reconstructions** informed by Ghidra static analysis. Native Android and iOS are not currently generated.
- Authentication schemes, signed requests, WebSockets, server-side state, anti-bot protections, and APIs unavailable to the capture tool may require additional work.
- Generated apps are not assumed to be production-ready. Review API calls, authentication, privacy, and permissions before deployment.
- Captured evidence can contain secrets or personal data. Keep HARs and screenshots private. Redaction catches common token/password patterns but cannot guarantee detection of every secret.
- Mimic does not invent successful server results. When the observed API or authentication cannot be used, the generated project should surface configuration/error states rather than pretend it works.

## Ethical use

Use this only to reproduce apps you own or have permission to test. Do not use it to impersonate third-party services, bypass access controls, or access other people's accounts or data. Respect the original service's terms and applicable law.

MIT license. See `LICENSE`.
