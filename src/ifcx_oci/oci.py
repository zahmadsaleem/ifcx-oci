"""OCI transfer is independent of IFC interpretation and payload codecs."""

import json
import os
import shutil
import subprocess
from pathlib import Path

from .contract import ARTIFACT_TYPE
from .release import verify


def oras_binary(argument):
    candidate = argument or os.environ.get("ORAS_BIN") or shutil.which("oras")
    if not candidate:
        raise ValueError("Install ORAS or set ORAS_BIN")
    return str(Path(candidate).resolve()) if "/" in candidate else candidate


def pack(root, destination, oras, layout=False, plain_http=False):
    root = root.resolve()
    verify(root)
    index = json.loads((root / "index.json").read_bytes())
    files = ["index.json:application/json"] + [
        x["path"] + ":" + x["mediaType"] for x in index["files"]
    ]
    flags = ["--oci-layout"] if layout else ["--plain-http"] if plain_http else []
    subprocess.run(
        [
            oras,
            "push",
            *flags,
            "--artifact-type",
            ARTIFACT_TYPE,
            "--annotation",
            "org.opencontainers.image.title=IFCX model release",
            destination,
            *files,
        ],
        cwd=root,
        check=True,
    )
