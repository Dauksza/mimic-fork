from __future__ import annotations

import argparse
import re
import sys

from .ollama import Ollama, OllamaError
from .reconstruct import reconstruct
from .sources import har, mitm


def main(argv=None):
    parser = argparse.ArgumentParser(prog='mimic-build', description='Reconstruct an authorized app as a runnable web project using local Ollama only.')
    parser.add_argument('host', help='API host from captured traffic')
    parser.add_argument('--har', metavar='FILE', help='read from a browser HAR export instead of live mitmweb')
    parser.add_argument('-o', '--out', help='output directory; must be new or empty')
    parser.add_argument('--name', help='display name for the reconstructed app')
    parser.add_argument('--model', default='qwen2.5-coder:14b', help='installed Ollama model')
    parser.add_argument('--ollama-url', default=None, help='Ollama URL; defaults to OLLAMA_HOST or localhost')
    parser.add_argument('--screenshots', default=None, help='directory containing screenshots of the target app (PNG/JPG/WebP)')
    args = parser.parse_args(argv)
    try:
        if args.har:
            endpoints = har.endpoints(args.har, args.host)
        else:
            proxy = mitm.Mitm()
            endpoints = mitm.endpoints(proxy, proxy.flows(), args.host)
        out = args.out or re.sub(r'[^a-z0-9]+', '-', args.host.split('.')[0].lower()).strip('-') + '-web'
        files = reconstruct(args.host, endpoints, out, app_name=args.name, model=args.model, base_url=args.ollama_url, screenshots_dir=args.screenshots)
    except (OllamaError, ValueError, FileExistsError, OSError) as exc:
        print('Build failed: ' + str(exc), file=sys.stderr)
        return 1
    print('Created ' + str(len(files)) + ' files in ' + out)
    print('\nRun the reconstructed app:')
    print('  cd ' + out)
    print('  npm install')
    print('  npm run dev')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
