#!/usr/bin/env python3
"""Validate docs/capabilities.json structure and verify referenced crates/modules exist."""
import json
from pathlib import Path
import sys

REQUIRED_KEYS = (
    "crate",
    "module",
    "path",
    "summary",
    "domain_aliases",
    "use_when",
    "avoid_when",
    "feature_gate",
)


def resolve_module_file(crate_dir: Path, module: str) -> Path | None:
    src_dir = crate_dir / "src"
    if module == "lib":
        candidate = src_dir / "lib.rs"
        return candidate if candidate.is_file() else None
    parts = module.split("::")
    direct = src_dir.joinpath(*parts[:-1], f"{parts[-1]}.rs")
    if direct.is_file():
        return direct
    nested = src_dir.joinpath(*parts, "mod.rs")
    if nested.is_file():
        return nested
    return None


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    cap_path = root / "docs" / "capabilities.json"
    if not cap_path.is_file():
        print(f"missing capabilities index: {cap_path}", file=sys.stderr)
        return 1

    try:
        data = json.loads(cap_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"invalid JSON in {cap_path}: {exc}", file=sys.stderr)
        return 1

    errors: list[str] = []
    if not isinstance(data, dict):
        errors.append("top-level JSON value must be an object")
    else:
        if data.get("schema_version") != 1:
            errors.append("schema_version must be 1")
        if data.get("toolkit") != "formatkit":
            errors.append("toolkit must be 'formatkit'")
        entries = data.get("capabilities")
        if not isinstance(entries, list) or not entries:
            errors.append("'capabilities' must be a non-empty array")
        else:
            seen: set[tuple[str, str, str]] = set()
            for idx, entry in enumerate(entries):
                prefix = f"capabilities[{idx}]"
                if not isinstance(entry, dict):
                    errors.append(f"{prefix}: entry must be an object")
                    continue
                missing = [k for k in REQUIRED_KEYS if k not in entry]
                if missing:
                    errors.append(f"{prefix}: missing keys {missing}")
                    continue

                for str_key in ("crate", "module", "path", "summary", "use_when", "avoid_when"):
                    val = entry[str_key]
                    if not isinstance(val, str) or not val.strip():
                        errors.append(f"{prefix}.{str_key}: must be a non-empty string")

                aliases = entry["domain_aliases"]
                if (
                    not isinstance(aliases, list)
                    or not aliases
                    or any(not isinstance(a, str) or not a.strip() for a in aliases)
                ):
                    errors.append(f"{prefix}.domain_aliases: must be a non-empty list of strings")

                gate = entry["feature_gate"]
                if gate is not None and (not isinstance(gate, str) or not gate.strip()):
                    errors.append(f"{prefix}.feature_gate: must be null or a non-empty string")

                crate_name = entry["crate"]
                module_name = entry["module"]
                path_name = entry["path"]
                key = (crate_name, module_name, path_name)
                if key in seen:
                    errors.append(f"{prefix}: duplicate capability entry {key}")
                seen.add(key)

                crate_dir = root / "crates" / crate_name
                if not (crate_dir / "Cargo.toml").is_file():
                    errors.append(f"{prefix}: crate '{crate_name}' does not exist under crates/")
                    continue

                if resolve_module_file(crate_dir, module_name) is None:
                    errors.append(
                        f"{prefix}: module '{module_name}' not found under crates/{crate_name}/src/"
                    )

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1

    print(f"Capabilities index: passed ({len(data['capabilities'])} entries verified)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
