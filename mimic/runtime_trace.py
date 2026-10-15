"""Optional, consent-driven Frida runtime metadata tracing for a selected Windows process.

Records module-load events and selected file/registry/network destination metadata.
It does not record keystrokes, clipboard contents, file contents, request payloads or passwords.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from pathlib import Path


class RuntimeTraceError(RuntimeError):
    pass


def _redact_windows_user_path(value):
    normalized = value.replace("/", "\\")
    parts = normalized.split("\\")
    for index, part in enumerate(parts[:-1]):
        if part.casefold() == "users":
            parts[index + 1] = "[USER]"
    return "\\".join(parts)


FRIDA_SCRIPT = r"""
'use strict';

const seen = new Set();
let emitted = 0;
const MAX_EVENTS = 2500;

function readWide(pointer, cap) {
  try {
    if (pointer.isNull()) return null;
    const value = pointer.readUtf16String(cap || 512);
    if (!value) return null;
    return value.length > 512 ? value.slice(0, 512) : value;
  } catch (_) { return null; }
}
function readAnsi(pointer, cap) {
  try {
    if (pointer.isNull()) return null;
    const value = pointer.readCString(cap || 512);
    if (!value) return null;
    return value.length > 512 ? value.slice(0, 512) : value;
  } catch (_) { return null; }
}
function record(kind, fields) {
  if (emitted >= MAX_EVENTS) return;
  const payload = Object.assign({type: kind, timestamp: new Date().toISOString()}, fields || {});
  const key = kind + ':' + JSON.stringify(fields || {});
  if (seen.has(key)) return;
  seen.add(key);
  emitted++;
  send(payload);
}
function findExport(moduleName, exportName) {
  try {
    if (Process.findModuleByName) {
      const module = Process.findModuleByName(moduleName);
      if (module && module.findExportByName) return module.findExportByName(exportName);
    }
  } catch (_) {}
  try {
    if (Module.findExportByName) return Module.findExportByName(moduleName, exportName);
  } catch (_) {}
  try {
    if (Module.findGlobalExportByName) return Module.findGlobalExportByName(exportName);
  } catch (_) {}
  return null;
}
function hook(moduleNames, exportName, onEnter) {
  for (const moduleName of moduleNames) {
    const address = findExport(moduleName, exportName);
    if (!address) continue;
    try {
      Interceptor.attach(address, {onEnter: function(args) {
        try { onEnter.call(this, args); } catch (_) {}
      }});
      record('instrumentation', {module: moduleName, api: exportName, state: 'hooked'});
      return true;
    } catch (_) {}
  }
  return false;
}

record('trace_start', {
  pid: Process.id,
  platform: Process.platform,
  architecture: Process.arch,
  pointer_size: Process.pointerSize
});

try {
  Process.attachModuleObserver({
    onAdded: function(module) {
      record('module_load', {
        name: module.name,
        path: module.path,
        base: module.base.toString(),
        size: module.size
      });
    }
  });
} catch (_) {}

const winModules = ['KERNELBASE.dll', 'kernel32.dll'];
hook(winModules, 'CreateFileW', function(args) {
  const path = readWide(args[0]);
  if (path) record('file_open_attempt', {path: path});
});
hook(winModules, 'DeleteFileW', function(args) {
  const path = readWide(args[0]);
  if (path) record('file_delete_attempt', {path: path});
});
hook(winModules, 'MoveFileExW', function(args) {
  const source = readWide(args[0]);
  const destination = readWide(args[1]);
  if (source || destination) record('file_move_attempt', {source: source, destination: destination});
});
hook(winModules, 'CopyFileW', function(args) {
  const source = readWide(args[0]);
  const destination = readWide(args[1]);
  if (source || destination) record('file_copy_attempt', {source: source, destination: destination});
});
hook(winModules, 'LoadLibraryW', function(args) {
  const path = readWide(args[0]);
  if (path) record('library_load_attempt', {path: path});
});
hook(winModules, 'LoadLibraryExW', function(args) {
  const path = readWide(args[0]);
  if (path) record('library_load_attempt', {path: path});
});
hook(['ADVAPI32.dll'], 'RegOpenKeyExW', function(args) {
  const path = readWide(args[1]);
  if (path) record('registry_open_attempt', {subkey: path});
});
hook(['ADVAPI32.dll'], 'RegCreateKeyExW', function(args) {
  const path = readWide(args[1]);
  if (path) record('registry_create_attempt', {subkey: path});
});
hook(['WINHTTP.dll'], 'WinHttpConnect', function(args) {
  const host = readWide(args[1]);
  const port = args[2].toInt32() & 0xffff;
  if (host) record('network_destination', {api: 'WinHttpConnect', host: host, port: port});
});
hook(['WININET.dll'], 'InternetConnectW', function(args) {
  const host = readWide(args[1]);
  const port = args[2].toInt32() & 0xffff;
  if (host) record('network_destination', {api: 'InternetConnectW', host: host, port: port});
});
// Winsock destination metadata captures apps that bypass WinHTTP/WinINet.
hook(['ws2_32.dll', 'WS2_32.dll'], 'getaddrinfo', function(args) {
  const host = readAnsi(args[0]);
  const service = readAnsi(args[1]);
  if (host || service) record('network_lookup', {api: 'getaddrinfo', host: host, service: service});
});
hook(['ws2_32.dll', 'WS2_32.dll'], 'GetAddrInfoW', function(args) {
  const host = readWide(args[0]);
  const service = readWide(args[1]);
  if (host || service) record('network_lookup', {api: 'GetAddrInfoW', host: host, service: service});
});
hook(['ws2_32.dll', 'WS2_32.dll'], 'connect', function(args) {
  try {
    const address = args[1];
    if (address.isNull()) return;
    const family = address.readU16();
    const port = ((address.add(2).readU8() & 0xff) << 8) | (address.add(3).readU8() & 0xff);
    if (family === 2) {
      const ip = [4, 5, 6, 7].map(function(offset) {
        return address.add(offset).readU8() & 0xff;
      }).join('.');
      record('network_destination', {api: 'connect', host: ip, port: port, address_family: 'IPv4'});
    } else if (family === 23) {
      const bytes = [];
      for (let i = 0; i < 16; i++) bytes.push((address.add(8 + i).readU8() & 0xff).toString(16).padStart(2, '0'));
      const groups = [];
      for (let i = 0; i < 16; i += 2) groups.push(bytes[i] + bytes[i + 1]);
      record('network_destination', {api: 'connect', host: groups.join(':'), port: port, address_family: 'IPv6'});
    }
  } catch (_) {}
});
hook(winModules, 'CreateProcessW', function(args) {
  const application = readWide(args[0]);
  // Deliberately do not read lpCommandLine; it can include passwords or tokens.
  if (application) record('process_launch_attempt', {application: application});
});
"""


class RuntimeTrace:
    def __init__(self, pid, output_path, on_status=None):
        self.pid = int(pid)
        self.output_path = Path(output_path).expanduser().resolve()
        self.on_status = on_status or (lambda message: None)
        self._stop = threading.Event()
        self._thread = None
        self._session = None
        self._script = None
        self._stream = None
        self._error = None
        self._count = 0

    @staticmethod
    def available():
        try:
            import frida  # noqa: F401
            return True
        except ImportError:
            return False

    def start(self):
        if not self.available():
            raise RuntimeTraceError('Frida is not installed. Install the optional dependency with: python -m pip install -e ".[instrumentation]"')
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self._stream = self.output_path.open("a", encoding="utf-8")
        self._thread = threading.Thread(target=self._worker, name="mimic-frida-trace", daemon=True)
        self._thread.start()
        self.on_status("Frida runtime trace starting for PID " + str(self.pid))
        return self

    def _write(self, record):
        record = dict(record)
        for key, value in list(record.items()):
            if isinstance(value, str):
                value = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", value)
                value = re.sub(r"(?i)(password|passwd|token|secret|api.?key|authorization|cookie)(\s*[:=]\s*)\S+", r"\1=[REDACTED]", value)
                value = _redact_windows_user_path(value)
                record[key] = value[:700]
        self._stream.write(json.dumps(record, ensure_ascii=False) + "\n")
        self._stream.flush()
        self._count += 1

    def _worker(self):
        try:
            import frida
            self._session = frida.attach(self.pid)
            self._script = self._session.create_script(FRIDA_SCRIPT)
            def on_message(message, data):
                if message.get("type") == "send":
                    payload = message.get("payload", {})
                    if isinstance(payload, dict):
                        self._write(payload)
                elif message.get("type") == "error":
                    self._write({"type": "instrumentation_error", "description": str(message.get("description", ""))[:400]})
            self._script.on("message", on_message)
            self._script.load()
            self.on_status("Frida attached. Recording selected file/registry/network metadata and loaded modules; payloads are excluded.")
            while not self._stop.wait(0.2):
                if self._error:
                    break
        except Exception as exc:
            self._error = str(exc)
            self.on_status("Frida runtime trace failed: " + str(exc)[:300])
        finally:
            try:
                if self._script:
                    self._script.unload()
            except Exception:
                pass
            try:
                if self._session:
                    self._session.detach()
            except Exception:
                pass
            if self._stream:
                try:
                    self._write({"type": "trace_end", "pid": self.pid, "events": self._count, "error": self._error})
                    self._stream.close()
                except Exception:
                    pass

    def stop(self):
        self._stop.set()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=12)
        if self._thread and self._thread.is_alive():
            self.on_status("Frida trace thread is still stopping; it will detach when the Frida transport returns.")
        else:
            self.on_status("Frida runtime trace saved to " + str(self.output_path))
        return {"output_path": str(self.output_path), "event_count": self._count, "error": self._error}
