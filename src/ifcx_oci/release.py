"""Build and verify a self-contained model release from neutral records."""

import hashlib
import json
import struct
import subprocess
import sys
import uuid
from pathlib import Path

import ifcopenshell
import pyarrow.parquet as pq

from .contract import PROFILE, SCHEMAS, canonical, description, encoded
from .extract import NAMESPACE
from .geometry import write_shards
from .store import Store


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded(value))


def file_hash(path):
    with path.open("rb") as source:
        return "sha256:" + hashlib.file_digest(source, "sha256").hexdigest()


def convert(source, output, shard_bytes, threads, resume=False):
    source = source.resolve()
    output = output.resolve()
    files = sorted(source.glob("*.ifc")) if source.is_dir() else [source]
    if not files:
        raise ValueError("No IFC files found")
    if len({p.name for p in files}) != len(files):
        raise ValueError("Model filenames must be unique")
    if output.exists() and not resume:
        raise ValueError(
            "Output already exists; choose a new directory or use --resume"
        )
    output.mkdir(parents=True, exist_ok=True)
    work = output / ".work"
    work.mkdir(exist_ok=True)
    reports = []
    for number, path in enumerate(files, 1):
        key = str(uuid.uuid5(NAMESPACE, "model:" + path.name))
        db = work / (key + ".sqlite")
        report_path = work / (key + ".json")
        if resume and report_path.exists():
            report = json.loads(report_path.read_bytes())
            if report.get("sourceSha256") != file_hash(path).removeprefix("sha256:"):
                raise ValueError(
                    "Source changed during resume; use a fresh output directory"
                )
            reports.append(report)
            print(
                f"Reusing completed extraction {number}/{len(files)}: {path.name}",
                flush=True,
            )
            continue
        # A failed worker may have committed partial rows; discard only its own spool.
        for suffix in ["", "-wal", "-shm"]:
            candidate = Path(str(db) + suffix)
            if candidate.exists():
                candidate.unlink()
        print(f"Source {number}/{len(files)}: {path.name}", flush=True)
        command = [
            sys.executable,
            "-m",
            "ifcx_oci.cli",
            "_extract",
            str(path),
            str(db),
            str(report_path),
            "--threads",
            str(threads),
        ]
        subprocess.run(command, check=True)
        reports.append(json.loads(report_path.read_bytes()))
    combined = work / "corpus.sqlite"
    for suffix in ["", "-wal", "-shm"]:
        p = Path(str(combined) + suffix)
        if p.exists():
            p.unlink()
    store = Store(combined)
    for path in files:
        key = str(uuid.uuid5(NAMESPACE, "model:" + path.name))
        store.db.execute(
            "ATTACH DATABASE ? AS source", (str(work / (key + ".sqlite")),)
        )
        store.db.execute("INSERT OR REPLACE INTO records SELECT * FROM source.records")
        store.db.execute("INSERT OR IGNORE INTO meshes SELECT * FROM source.meshes")
        store.commit()
        store.db.execute("DETACH DATABASE source")
    print("Writing shared geometry and size-bounded Parquet layers...", flush=True)
    # Resume can change the shard target. Remove superseded generated shards so
    # reading a layer directory never includes stale rows from an earlier build.
    (output / "index.json").unlink(missing_ok=True)
    for kind in [*SCHEMAS, "geometry"]:
        extension = "*.glb" if kind == "geometry" else "*.parquet"
        for old in (output / kind).glob(extension):
            old.unlink()
    payloads = write_shards(store, output, shard_bytes)
    for kind in SCHEMAS:
        payloads.extend(store.parquet_shards(kind, output, shard_bytes))
    contract = output / "schema/profile.json"
    write_json(contract, description())
    payloads.append(
        {
            "path": "schema/profile.json",
            "role": "schema",
            "mediaType": "application/json",
        }
    )
    sources = output / "sources.json"
    write_json(sources, reports)
    payloads.append(
        {"path": "sources.json", "role": "provenance", "mediaType": "application/json"}
    )
    counts = dict(store.db.execute("SELECT kind,count(*) FROM records GROUP BY kind"))
    mesh_count = store.db.execute("SELECT count(*) FROM meshes").fetchone()[0]
    for item in payloads:
        path = output / item["path"]
        item.update(size=path.stat().st_size, digest=file_hash(path))
    index = {
        "profile": PROFILE,
        "status": "experimental IFCX binary proposal",
        "ifcopenshellVersion": ifcopenshell.version,
        "shardTargetBytes": shard_bytes,
        "coordinateSystem": "Y-up, right-handed, metres",
        "sourceFiles": len(files),
        "rowCounts": counts,
        "uniqueGeometry": mesh_count,
        "files": sorted(payloads, key=lambda x: x["path"]),
        "geometryCoverage": {
            "representedProducts": sum(r["representedProducts"] for r in reports),
            "meshedProducts": sum(r["meshedProducts"] for r in reports),
            "missingGeometry": sum(len(r["missingGeometry"]) for r in reports),
            "maxQuantizationErrorM": max(
                (r["maxQuantizationErrorM"] for r in reports), default=0
            ),
        },
    }
    write_json(output / "index.json", index)
    store.close()
    print(
        canonical(
            {
                "output": str(output),
                "counts": counts,
                "uniqueGeometry": mesh_count,
                "payloadBytes": sum(x["size"] for x in payloads),
                "shards": len(payloads),
                "geometryCoverage": index["geometryCoverage"],
            }
        ),
        flush=True,
    )
    return index


def verify(root):
    root = root.resolve()
    index = json.loads((root / "index.json").read_bytes())
    if index["profile"] != PROFILE:
        raise ValueError("Unknown profile")
    ids = set()
    types = set()
    geometries = set()
    geometry_files = set()
    geometry_nodes = set()
    property_ids = set()
    references = set()
    counts = {}

    def attribute_references(value):
        if isinstance(value, dict):
            if "$ref" in value:
                references.add(("owner", value["$ref"]))
            for child in value.values():
                attribute_references(child)
        elif isinstance(value, list):
            for child in value:
                attribute_references(child)

    for item in index["files"]:
        relative = Path(item["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Unsafe package path")
        path = root / relative
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError("Package path escaped root")
        if file_hash(path) != item["digest"] or path.stat().st_size != item["size"]:
            raise ValueError("Payload integrity failed: " + str(relative))
        kind = item["role"]
        if kind in SCHEMAS or kind == "geometry":
            oversized = item["size"] > index["shardTargetBytes"]
            if oversized != item["oversized"]:
                raise ValueError("Incorrect shard size declaration")
            records = item["meshes"] if kind == "geometry" else item["rows"]
            if oversized and records != 1:
                raise ValueError(
                    "Oversized shards may contain only one indivisible record"
                )
        if kind == "geometry":
            geometry_files.add(item["path"])
            with path.open("rb") as f:
                header = f.read(12)
                chunk_size, chunk_kind = struct.unpack("<I4s", f.read(8))
                if chunk_kind != b"JSON":
                    raise ValueError("GLB first chunk must be JSON")
                document = json.loads(f.read(chunk_size))
                for number, node in enumerate(document["nodes"]):
                    geometry_nodes.add(
                        (item["path"], number, node["extras"]["representationId"])
                    )

            if struct.unpack("<4sII", header) != (b"glTF", 2, item["size"]):
                raise ValueError("Invalid GLB header")
        if kind not in SCHEMAS:
            continue
        f = pq.ParquetFile(path)
        if not f.schema_arrow.equals(SCHEMAS[kind], check_metadata=True):
            raise ValueError("Parquet schema mismatch: " + kind)
        for batch in f.iter_batches(batch_size=8192):
            rows = batch.to_pylist()
            counts[kind] = counts.get(kind, 0) + len(rows)
            for row in rows:
                if "attributes" in row:
                    attributes = json.loads(row["attributes"])
                    if (
                        not isinstance(attributes, dict)
                        or canonical(attributes) != row["attributes"]
                    ):
                        raise ValueError("attributes must be a canonical JSON object")
                    attribute_references(attributes)
                if kind == "types":
                    types.add(row["id"])
                elif kind == "entities":
                    ids.add(row["id"])
                    if row["type_id"]:
                        references.add(("type", row["type_id"]))
                    if row["geometry_id"]:
                        references.add(("geometry", row["geometry_id"]))
                    if row["transform"] is not None and len(row["transform"]) != 16:
                        raise ValueError("Invalid transform")
                elif kind == "representations":
                    geometries.add(row["id"])
                    references.add(("blob", row["blob"]))
                    references.add(
                        ("geometryNode", (row["blob"], row["node"], row["id"]))
                    )
                elif kind == "properties":
                    property_ids.add(row["id"])
                    references.add(("owner", row["owner_id"]))
                    references.add(("entity", row["pset_id"]))
                    if row["parent_id"]:
                        references.add(("property", row["parent_id"]))
                    for value in row["values"]:
                        if value["reference"] is not None:
                            target = json.loads(value["reference"])
                            if (
                                not isinstance(target, dict)
                                or canonical(target) != value["reference"]
                            ):
                                raise ValueError(
                                    "Property reference must be a canonical JSON object"
                                )
                            attribute_references(target)
                elif kind == "relations":
                    references.update(
                        [
                            ("entity", row["relationship_id"]),
                            ("owner", row["target_id"]),
                        ]
                    )
    domains = {
        "type": types,
        "geometry": geometries,
        "blob": geometry_files,
        "owner": ids | types,
        "entity": ids,
        "property": property_ids,
        "geometryNode": geometry_nodes,
    }
    for kind, target in references:
        if target not in domains[kind]:
            raise ValueError(f"Unresolved {kind} reference: {target}")
    if counts != index["rowCounts"]:
        raise ValueError("Row counts differ from index")
    return {
        "valid": True,
        "rowCounts": counts,
        "geometry": len(geometries),
        "uniqueReferenceTargetsChecked": len(references),
    }
