"""Command parsing and delegation to extraction, release and transfer workflows."""

import argparse
import subprocess
from pathlib import Path

from .contract import canonical
from .extract import extract_file
from .oci import oras_binary, pack
from .release import convert, verify, write_json


def main():
    parser = argparse.ArgumentParser(
        description="IFC → shared types, GLB and Parquet → OCI"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    c = sub.add_parser("convert")
    c.add_argument("source", type=Path)
    c.add_argument("--output", type=Path, required=True)
    c.add_argument("--shard-mib", type=float, default=8)
    c.add_argument("--threads", type=int, default=4)
    c.add_argument("--resume", action="store_true")
    w = sub.add_parser("_extract", help=argparse.SUPPRESS)
    w.add_argument("source", type=Path)
    w.add_argument("database", type=Path)
    w.add_argument("report", type=Path)
    w.add_argument("--threads", type=int, default=4)
    v = sub.add_parser("verify")
    v.add_argument("directory", type=Path)
    p = sub.add_parser("push")
    p.add_argument("directory", type=Path)
    p.add_argument("destination")
    p.add_argument("--oras")
    p.add_argument("--oci-layout", action="store_true")
    p.add_argument("--plain-http", action="store_true")
    cp = sub.add_parser("copy")
    cp.add_argument("source")
    cp.add_argument("destination")
    cp.add_argument("--oras")
    cp.add_argument("--plain-http", action="store_true")
    pull = sub.add_parser("pull")
    pull.add_argument("source")
    pull.add_argument("--output", type=Path, required=True)
    pull.add_argument("--oras")
    pull.add_argument("--oci-layout", action="store_true")
    pull.add_argument("--plain-http", action="store_true")
    args = parser.parse_args()
    if args.command == "convert":
        if args.shard_mib < 0.0625 or args.threads < 1:
            parser.error("Use >= 0.0625 MiB shards and >= 1 worker thread")
        convert(
            args.source,
            args.output,
            int(args.shard_mib * 1024**2),
            args.threads,
            args.resume,
        )
    elif args.command == "_extract":
        write_json(args.report, extract_file(args.source, args.database, args.threads))
    elif args.command == "verify":
        print(canonical(verify(args.directory)))
    elif args.command == "push":
        pack(
            args.directory,
            args.destination,
            oras_binary(args.oras),
            args.oci_layout,
            args.plain_http,
        )
    elif args.command == "copy":
        flags = ["--from-plain-http", "--to-plain-http"] if args.plain_http else []
        subprocess.run(
            [oras_binary(args.oras), "cp", "-r", *flags, args.source, args.destination],
            check=True,
        )
    elif args.command == "pull":
        if args.output.exists() and (
            not args.output.is_dir() or any(args.output.iterdir())
        ):
            parser.error("Pull output must be a new or empty directory")
        flags = (
            ["--oci-layout"]
            if args.oci_layout
            else ["--plain-http"]
            if args.plain_http
            else []
        )
        subprocess.run(
            [
                oras_binary(args.oras),
                "pull",
                *flags,
                "--output",
                str(args.output),
                args.source,
            ],
            check=True,
        )
        print(canonical(verify(args.output)))


if __name__ == "__main__":
    main()
