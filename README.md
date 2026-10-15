# mimic — local app capture and reconstruction

Mimic records traffic from an app you own or are authorized to test, analyzes the observed API, and can generate either a Python API client or a runnable React/Vite web reconstruction. **All AI generation uses your local Ollama server; there is no cloud AI provider or API key.**

It cannot recover the original private source code. It reconstructs observable behavior from captured network requests, responses, and optional screenshots. Better evidence produces a better result; unobserved screens and workflows remain inferred.

## What it can build today

- **Traffic evidence:** browser HAR files or live mitmproxy capture.
- **Endpoint inventory:** host, method, path, status, request/response examples.
- **Python API client:** generated locally with Ollama.
- **Web app reconstruction:** React/Vite project with navigation, responsive styling, forms, API integration, loading/error/empty states, setup instructions, and a coverage report.
- **Visual evidence:** supply screenshots; a vision-capable Ollama model can use them to infer layout and styling.
- **Safety checks:** generated paths are validated; captured auth headers are not sent as part of the endpoint digest; common token/password fields in captured bodies are redacted; captured credentials are not exported into generated source.

## Requirements

- Python 3.9+
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
- The current project generator targets **web apps (React/Vite)**. It does not generate native Android, iOS, or desktop applications.
- Authentication schemes, signed requests, WebSockets, server-side state, anti-bot protections, and APIs unavailable to the capture tool may require additional work.
- Generated apps are not assumed to be production-ready. Review API calls, authentication, privacy, and permissions before deployment.
- Captured evidence can contain secrets or personal data. Keep HARs and screenshots private. Redaction catches common token/password patterns but cannot guarantee detection of every secret.
- Mimic does not invent successful server results. When the observed API or authentication cannot be used, the generated project should surface configuration/error states rather than pretend it works.

## Ethical use

Use this only to reproduce apps you own or have permission to test. Do not use it to impersonate third-party services, bypass access controls, or access other people's accounts or data. Respect the original service's terms and applicable law.

MIT license. See `LICENSE`.
