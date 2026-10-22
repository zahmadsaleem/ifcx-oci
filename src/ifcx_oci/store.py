"""A disk spool permits deduplication and size bounded, stable hash partitions."""

import hashlib
import json
import sqlite3

import pyarrow as pa
import pyarrow.parquet as pq

from .contract import SCHEMAS, encoded


class Store:
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("PRAGMA cache_size=-65536")
        self.pending_records = 0
        self.db.execute("""CREATE TABLE IF NOT EXISTS records(
            kind TEXT, id TEXT, key TEXT, payload BLOB, size INTEGER, PRIMARY KEY(kind,id))""")
        self.db.execute(
            "CREATE INDEX IF NOT EXISTS partition_index ON records(kind,key)"
        )
        self.db.execute("""CREATE TABLE IF NOT EXISTS meshes(
            id TEXT PRIMARY KEY, key TEXT, positions BLOB, indices BLOB, materials BLOB, meta BLOB, size INTEGER)""")
        self.db.execute("CREATE INDEX IF NOT EXISTS mesh_partition ON meshes(key)")

    def put(self, kind, row):
        payload = encoded(row)
        self.db.execute(
            "INSERT OR REPLACE INTO records VALUES(?,?,?,?,?)",
            (
                kind,
                row["id"],
                hashlib.sha256(row["id"].encode()).hexdigest(),
                payload,
                len(payload),
            ),
        )
        self.pending_records += 1
        if self.pending_records >= 2000:
            self.commit()

    def update_geometry(self, identifier, geometry_id, transform):
        result = self.db.execute(
            "SELECT payload FROM records WHERE kind='entities' AND id=?", (identifier,)
        ).fetchone()
        if result is None:
            raise ValueError(f"Geometry has no exported entity: {identifier}")
        row = json.loads(result[0])
        row.update(geometry_id=geometry_id, transform=transform)
        self.put("entities", row)

    def commit(self):
        self.db.commit()
        self.pending_records = 0

    def close(self):
        self.commit()
        self.db.close()

    def parquet_shards(self, kind, root, target):
        directory = root / kind
        directory.mkdir(parents=True, exist_ok=True)
        result = []

        def partition(prefix):
            count, total = self.db.execute(
                "SELECT count(*),coalesce(sum(size),0) FROM records WHERE kind=? AND key LIKE ?",
                (kind, prefix + "%"),
            ).fetchone()
            if not count:
                return
            # Bound RAM before attempting compression. Final byte size is checked below.
            if total > target * 8 and count > 1:
                for ch in "0123456789abcdef":
                    partition(prefix + ch)
                return
            rows = [
                json.loads(x[0])
                for x in self.db.execute(
                    "SELECT payload FROM records WHERE kind=? AND key LIKE ? ORDER BY id",
                    (kind, prefix + "%"),
                )
            ]
            path = directory / ((prefix or "root") + ".parquet")
            table = pa.Table.from_pylist(rows, schema=SCHEMAS[kind])
            pq.write_table(
                table,
                path,
                compression="zstd",
                compression_level=6,
                row_group_size=8192,
                use_dictionary=True,
                write_page_index=True,
            )
            if path.stat().st_size > target and count > 1:
                path.unlink()
                for ch in "0123456789abcdef":
                    partition(prefix + ch)
            else:
                result.append(
                    {
                        "path": path.relative_to(root).as_posix(),
                        "role": kind,
                        "mediaType": "application/vnd.apache.parquet",
                        "rows": count,
                        "oversized": path.stat().st_size > target,
                    }
                )

        partition("")
        return result
