from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

import typer
from rich.console import Console

from .state import CLIState, GlobalOptions

console = Console()

try:
    import orjson  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    import json

    def _dumps(data: Any) -> bytes:
        return json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
else:
    def _dumps(data: Any) -> bytes:
        return orjson.dumps(data, option=orjson.OPT_INDENT_2)  # type: ignore[attr-defined]


try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover
    yaml = None  # type: ignore


def ensure_state(ctx: typer.Context) -> CLIState:
    obj = ctx.obj
    if isinstance(obj, CLIState):
        return obj
    state = CLIState(options=GlobalOptions())
    ctx.obj = state
    return state


def emit_json(payload: Dict[str, Any], target: Optional[str], fallback: Optional[str]) -> None:
    destination = target or fallback
    data = _dumps(payload)
    if destination in (None, "-"):
        console.print_json(data=data.decode("utf-8"))
    else:
        Path(destination).write_bytes(data)
        console.print(f"[success]JSON escrito em {destination}")


def emit_yaml(payload: Dict[str, Any], target: Optional[str], fallback: Optional[str]) -> None:
    if yaml is None:
        raise typer.BadParameter("PyYAML é necessário para saída YAML, instale a dependência.")
    destination = target or fallback
    data = yaml.safe_dump(payload, sort_keys=False)
    if destination in (None, "-"):
        console.print(data)
    else:
        Path(destination).write_text(data, encoding="utf-8")
        console.print(f"[success]YAML escrito em {destination}")


__all__ = ["console", "ensure_state", "emit_json", "emit_yaml"]
