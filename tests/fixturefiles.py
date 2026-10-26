# ABOUTME: Loads the JSON fixtures under tests/fixtures: spec-example API bodies and MC-shaped scenarios.
# ABOUTME: Each file names its source in "_source"; the loopback seam strips that key before serving it.

import json
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def load(kind, name):
    """A fixture's parsed JSON, freshly read so a test may change its copy: kind is the directory."""
    return json.loads((FIXTURES / kind / f"{name}.json").read_text(encoding="utf-8"))


def body(kind, name):
    """A fixture as the API would send it: the same object without its "_source" label."""
    doc = load(kind, name)
    doc.pop("_source", None)
    return doc
