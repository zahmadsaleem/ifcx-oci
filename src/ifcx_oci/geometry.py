"""Pack neutral indexed meshes into independently fetchable GLB shards."""

import json
import struct

import numpy as np

from .contract import canonical


def glb(meshes):
    doc = {
        "asset": {"version": "2.0", "generator": "ifcx-oci/0.1"},
        "scene": 0,
        "scenes": [{"nodes": []}],
        "nodes": [],
        "meshes": [],
        "materials": [],
        "buffers": [{"byteLength": 0}],
        "bufferViews": [],
        "accessors": [],
    }
    data = bytearray()
    rows = []
    material_cache = {}

    def accessor(payload, component_type, count, kind, target, bounds=None):
        data.extend(b"\0" * (-len(data) % 4))
        offset = len(data)
        data.extend(payload)
        view = len(doc["bufferViews"])
        doc["bufferViews"].append(
            {
                "buffer": 0,
                "byteOffset": offset,
                "byteLength": len(payload),
                "target": target,
            }
        )
        item = {
            "bufferView": view,
            "componentType": component_type,
            "count": count,
            "type": kind,
        }
        if bounds:
            item.update(min=bounds[0], max=bounds[1])
        index = len(doc["accessors"])
        doc["accessors"].append(item)
        return index

    for identifier, positions, indices, material_ids, metadata in meshes:
        meta = json.loads(metadata)
        p = accessor(
            positions, 5126, meta["vertices"], "VEC3", 34962, (meta["min"], meta["max"])
        )
        faces = np.frombuffer(indices, dtype="<u4").reshape(-1, 3)
        ids = np.frombuffer(material_ids, dtype="<i4")
        if len(ids) != len(faces):
            ids = np.full(len(faces), -1, dtype=np.int32)
        primitives = []
        for material_id in sorted(set(ids.tolist())):
            selected = faces[ids == material_id].astype("<u4")
            ix = accessor(selected.tobytes(), 5125, selected.size, "SCALAR", 34963)
            primitive = {"attributes": {"POSITION": p}, "indices": ix}
            if 0 <= material_id < len(meta["materials"]):
                rgba = meta["materials"][material_id]
                key = tuple(rgba)
                if key not in material_cache:
                    material_cache[key] = len(doc["materials"])
                    material = {
                        "pbrMetallicRoughness": {
                            "baseColorFactor": rgba,
                            "metallicFactor": 0.0,
                            "roughnessFactor": 0.8,
                        },
                        "doubleSided": True,
                    }
                    if rgba[3] < 1.0:
                        material["alphaMode"] = "BLEND"
                    doc["materials"].append(material)
                primitive["material"] = material_cache[key]
            primitives.append(primitive)
        mesh_index = len(doc["meshes"])
        doc["meshes"].append({"primitives": primitives})
        node_index = len(doc["nodes"])
        doc["nodes"].append(
            {
                "mesh": mesh_index,
                "translation": meta["origin"],
                "extras": {"representationId": identifier},
            }
        )
        doc["scenes"][0]["nodes"].append(node_index)
        rows.append(
            {
                "id": identifier,
                "node": node_index,
                "vertices": meta["vertices"],
                "triangles": meta["triangles"],
                "quantization_error_m": meta["quantization_error_m"],
            }
        )
    doc["buffers"][0]["byteLength"] = len(data)
    if not doc["materials"]:
        del doc["materials"]
    j = canonical(doc).encode()
    j += b" " * (-len(j) % 4)
    data.extend(b"\0" * (-len(data) % 4))
    total = 12 + 8 + len(j) + 8 + len(data)
    return (
        struct.pack("<4sII", b"glTF", 2, total)
        + struct.pack("<I4s", len(j), b"JSON")
        + j
        + struct.pack("<I4s", len(data), b"BIN\0")
        + data
    ), rows


def write_shards(store, root, target):
    directory = root / "geometry"
    directory.mkdir(parents=True, exist_ok=True)
    files = []

    def partition(prefix):
        count, total = store.db.execute(
            "SELECT count(*),coalesce(sum(size),0) FROM meshes WHERE key >= ? AND key < ?",
            (prefix, prefix + "g"),
        ).fetchone()
        if not count:
            return
        if total > target and count > 1:
            for ch in "0123456789abcdef":
                partition(prefix + ch)
            return
        meshes = store.db.execute(
            "SELECT id,positions,indices,materials,meta FROM meshes WHERE key >= ? AND key < ? ORDER BY id",
            (prefix, prefix + "g"),
        ).fetchall()
        payload, representations = glb(meshes)
        if len(payload) > target and count > 1:
            for ch in "0123456789abcdef":
                partition(prefix + ch)
            return
        path = directory / ((prefix or "root") + ".glb")
        path.write_bytes(payload)
        relative = path.relative_to(root).as_posix()
        for row in representations:
            store.put("representations", {**row, "blob": relative})
        files.append(
            {
                "path": relative,
                "role": "geometry",
                "mediaType": "model/gltf-binary",
                "meshes": count,
                "oversized": len(payload) > target,
            }
        )

    partition("")
    store.commit()
    return files
