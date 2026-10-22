import hashlib
import json
import uuid

import pyarrow.parquet as pq

from ifcx_oci.contract import canonical
from ifcx_oci.store import Store


def test_size_bounded_shards_rebuild_identically_and_isolate_an_insert(tmp_path):
    store = Store(tmp_path / "records.sqlite")
    for i in range(100):
        tokens = [hashlib.sha256(f"{i}:{n}".encode()).hexdigest() for n in range(80)]
        store.put(
            "entities",
            {
                "id": str(uuid.uuid5(uuid.NAMESPACE_URL, str(i))),
                "model_id": "test",
                "ifc_class": "IfcWall",
                "source_step_id": i,
                "attributes": canonical({"tokens": tokens}),
                "global_id": None,
                "type_id": None,
                "geometry_id": None,
                "transform": None,
            },
        )
    target = 32 * 1024
    first, repeat, updated = [
        tmp_path / name for name in ["first", "repeat", "updated"]
    ]
    files = store.parquet_shards("entities", first, target)
    assert len(files) > 1
    assert all((first / f["path"]).stat().st_size <= target for f in files)
    assert (
        sum(pq.ParquetFile(first / f["path"]).metadata.num_rows for f in files) == 100
    )
    assert all(not f["oversized"] for f in files)
    store.parquet_shards("entities", repeat, target)

    def identities(root):
        return {
            p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob("*.parquet")
        }

    assert identities(first) == identities(repeat)
    row = json.loads(
        store.db.execute("SELECT payload FROM records LIMIT 1").fetchone()[0]
    )
    row["id"] = str(uuid.uuid5(uuid.NAMESPACE_URL, "inserted"))
    store.put("entities", row)
    store.parquet_shards("entities", updated, target)
    old, new = identities(first), identities(updated)
    assert any(new.get(name) == value for name, value in old.items())
    assert old != new
    store.close()
