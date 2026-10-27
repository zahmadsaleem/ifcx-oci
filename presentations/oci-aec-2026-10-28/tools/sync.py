#!/usr/bin/env python3
"""Synchronize a validated complete bundle without copying legacy drafts."""
import argparse
import json
from pathlib import Path
import shutil
import sys

sys.dont_write_bytecode = True
from prepare_site import PUBLIC_FILES, TOOL_FILES, digest, retired_files, validate_bundle

DESTINATION = Path(__file__).resolve().parents[1]


def synchronize(source):
    source = source.resolve()
    if source == DESTINATION or DESTINATION.is_relative_to(source):
        raise ValueError("Choose a separate approved source bundle.")
    report = validate_bundle(source)
    recorded = json.loads((source / "tools/verification.json").read_text())
    if recorded != report:
        raise ValueError("Validate the source bundle and refresh its portable report first.")
    files = PUBLIC_FILES + TOOL_FILES
    before = {name: digest(source / name) for name in files}
    for name in files:
        path = source / name
        if path.is_symlink():
            raise ValueError("Bundle resources must be ordinary files.")
    for name in files:
        target = DESTINATION / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists() or digest(target) != before[name]:
            shutil.copyfile(source / name, target)
    for path in retired_files(DESTINATION):
        path.unlink()
    assert before == {name: digest(source / name) for name in files}
    assert before == {name: digest(DESTINATION / name) for name in files}
    assert validate_bundle(DESTINATION) == report
    print(json.dumps({"slides": report["slides"], "notes": report["notes"], "filesMatch": len(files), "sourceUnchanged": True}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="Approved complete bundle; local paths are not stored in the repository.")
    synchronize(parser.parse_args().source)
