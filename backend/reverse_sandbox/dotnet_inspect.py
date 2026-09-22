#!/usr/bin/env python3
"""Bounded static .NET metadata inspection using dnfile/dncil."""

from __future__ import annotations

import json
import sys


def text(value) -> str:
    return str(value or "")[:1000]


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: dotnet-inspect <pe>", file=sys.stderr)
        return 2
    try:
        import dnfile
        import dncil

        pe = dnfile.dnPE(sys.argv[1])
        if not getattr(pe, "net", None):
            raise ValueError("input has no .NET metadata directory")
        tables = getattr(pe.net, "mdtables", None)
        types = []
        methods = []
        typedef = getattr(tables, "TypeDef", None) if tables else None
        methoddef = getattr(tables, "MethodDef", None) if tables else None
        for row in list(getattr(typedef, "rows", []) or [])[:5000]:
            types.append({"namespace": text(getattr(row, "TypeNamespace", "")),
                          "name": text(getattr(row, "TypeName", "")),
                          "flags": int(getattr(row, "Flags", 0) or 0)})
        for row in list(getattr(methoddef, "rows", []) or [])[:10_000]:
            methods.append({"name": text(getattr(row, "Name", "")),
                            "rva": int(getattr(row, "Rva", 0) or 0),
                            "flags": int(getattr(row, "Flags", 0) or 0)})
        print(json.dumps({"success": True, "format": ".NET PE", "types": types,
                          "methods": methods, "type_count": len(types),
                          "method_count": len(methods),
                          "versions": {"dnfile": dnfile.__version__,
                                       "dncil": getattr(dncil, "__version__", "installed")}},
                         indent=2, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"success": False, "error": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
