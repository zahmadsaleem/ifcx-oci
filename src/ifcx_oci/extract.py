"""IFC interpretation. Serializers consume the neutral records produced here."""

import base64
import hashlib
import json
import math
import uuid
from collections import Counter
from pathlib import Path

import ifcopenshell
import ifcopenshell.geom
import ifcopenshell.util.element
import numpy as np

from .contract import canonical, encoded

NAMESPACE = uuid.UUID("e9b05a61-c05c-4892-b30b-945680f16449")
C = np.array([[1.0, 0, 0, 0], [0, 0, 1.0, 0], [0, -1.0, 0, 0], [0, 0, 0, 1.0]])


class Extractor:
    def __init__(self, model, model_id, store):
        self.model = model
        self.model_id = model_id
        self.store = store
        self.namespace = uuid.UUID(model_id)
        self.root_ids = {e.id() for e in model.by_type("IfcRoot")}
        counts = Counter(e.GlobalId for e in model.by_type("IfcRoot"))
        self.duplicate_guids = {key for key, count in counts.items() if count > 1}
        self.identifiers = {}
        self.property_kinds = {}

    def identifier(self, entity):
        step_id = entity.id()
        if step_id in self.identifiers:
            return self.identifiers[step_id]
        key = getattr(entity, "GlobalId", None) or f"step:{entity.id()}"
        if key in self.duplicate_guids:
            key += f":step:{entity.id()}"
        result = str(uuid.uuid5(self.namespace, key))
        self.identifiers[step_id] = result
        return result

    def value(self, value):
        if isinstance(value, ifcopenshell.entity_instance):
            if value.id() == 0:
                return {
                    "$ifcType": value.is_a(),
                    "value": self.value(value.wrappedValue),
                }
            if value.id() in self.root_ids:
                return {"$ref": self.identifier(value)}
            return {"$sourceRef": value.id(), "ifcClass": value.is_a()}
        if isinstance(value, (tuple, list)):
            return [self.value(x) for x in value]
        if isinstance(value, float) and not math.isfinite(value):
            return {
                "$nonFinite": "NaN"
                if math.isnan(value)
                else "Infinity"
                if value > 0
                else "-Infinity"
            }
        if (
            isinstance(value, int)
            and not isinstance(value, bool)
            and not -(2**63) <= value < 2**63
        ):
            return {"$integer": str(value)}
        if isinstance(value, bytes):
            return {"$binary": base64.b64encode(value).decode()}
        return value

    def attributes(self, entity):
        return {
            entity.attribute_name(i): self.value(entity[i]) for i in range(len(entity))
        }

    def unit(self, unit):
        if unit is None:
            return None

        # Units are small structured metadata. Follow forward values only, with cycle protection.
        def convert(x, seen):
            if isinstance(x, ifcopenshell.entity_instance):
                if x.id() == 0:
                    return self.value(x)
                if x.id() in seen:
                    return self.value(x)
                return {
                    "ifcClass": x.is_a(),
                    **{
                        x.attribute_name(i): convert(x[i], seen | {x.id()})
                        for i in range(len(x))
                    },
                }
            if isinstance(x, (tuple, list)):
                return [convert(v, seen) for v in x]
            return self.value(x)

        return canonical(convert(unit, set()))

    def tagged(self, value, role, index=0):
        if value is None:
            return None
        ifc_type = (
            value.is_a()
            if isinstance(value, ifcopenshell.entity_instance)
            else type(value).__name__
        )
        raw = (
            value.wrappedValue
            if isinstance(value, ifcopenshell.entity_instance) and value.id() == 0
            else value
        )
        result = {"role": role, "index": index, "ifc_type": ifc_type}
        if isinstance(raw, bool):
            result["boolean"] = raw
        elif isinstance(raw, int) and -(2**63) <= raw < 2**63:
            result["integer"] = raw
        elif isinstance(raw, float) and math.isfinite(raw):
            result["real"] = raw
        elif isinstance(raw, str):
            result["text"] = raw
        elif isinstance(raw, (list, tuple)) and all(
            isinstance(x, int) and -(2**63) <= x < 2**63 for x in raw
        ):
            result["components_integer"] = list(raw)
        elif isinstance(raw, (list, tuple)) and all(
            isinstance(x, (int, float)) and math.isfinite(x) for x in raw
        ):
            result["components_real"] = list(raw)
        elif isinstance(raw, ifcopenshell.entity_instance):
            result["reference"] = canonical(self.value(raw))
        else:
            result["text"] = canonical(self.value(raw))
        return result

    def property_set(self, owner, pset, occurrence):
        owner_id = self.identifier(owner)
        pset_id = self.identifier(pset)
        owner_kind = "type" if owner.is_a("IfcTypeObject") else "entity"
        name = getattr(pset, "Name", None) or pset.is_a()
        prefix = "/" + name.replace("~", "~0").replace("/", "~1") + f"@{occurrence}"

        def visit(prop, path, parent, group=False):
            pid = str(uuid.uuid5(uuid.UUID(owner_id), pset_id + path))
            kind = (
                "set"
                if group
                else "quantity"
                if prop.is_a("IfcPhysicalQuantity")
                else prop.is_a()
            )
            row = {
                "id": pid,
                "model_id": self.model_id,
                "owner_id": owner_id,
                "owner_kind": owner_kind,
                "pset_id": pset_id,
                "parent_id": parent,
                "path": path,
                "name": getattr(prop, "Name", None) or prop.is_a(),
                "ifc_class": prop.is_a(),
                "kind": kind,
                "description": getattr(prop, "Description", None),
                "usage_name": getattr(prop, "UsageName", None),
                "discrimination": getattr(prop, "Discrimination", None),
                "quality": getattr(prop, "Quality", None),
                "usage": getattr(prop, "Usage", None),
                "unit": self.unit(getattr(prop, "Unit", None)),
                "defining_unit": self.unit(getattr(prop, "DefiningUnit", None)),
                "defined_unit": self.unit(getattr(prop, "DefinedUnit", None)),
                "expression": getattr(prop, "Expression", None),
                "interpolation": getattr(prop, "CurveInterpolation", None),
                "values": [],
            }
            members = (
                getattr(prop, "HasProperties", None)
                or getattr(prop, "Quantities", None)
                or getattr(prop, "HasQuantities", None)
                or ()
            )
            columns = []
            if prop.is_a("IfcPropertySingleValue"):
                columns = [("value", [prop.NominalValue])]
            elif prop.is_a("IfcPropertyListValue"):
                columns = [("item", prop.ListValues or [])]
            elif prop.is_a("IfcPropertyEnumeratedValue"):
                columns = [("selected", prop.EnumerationValues or [])]
                ref = prop.EnumerationReference
                if ref is not None:
                    columns.append(("allowed", ref.EnumerationValues or []))
                    row["unit"] = self.unit(ref.Unit)
            elif prop.is_a("IfcPropertyBoundedValue"):
                columns = [
                    (r, [getattr(prop, a, None)])
                    for r, a in [
                        ("lower", "LowerBoundValue"),
                        ("upper", "UpperBoundValue"),
                        ("setPoint", "SetPointValue"),
                    ]
                ]
            elif prop.is_a("IfcPropertyTableValue"):
                columns = [
                    ("defining", prop.DefiningValues or []),
                    ("defined", prop.DefinedValues or []),
                ]
            elif prop.is_a("IfcPropertyReferenceValue"):
                columns = [("reference", [prop.PropertyReference])]
            elif prop.is_a("IfcPhysicalSimpleQuantity"):
                columns = [
                    ("value", [prop[i]])
                    for i in range(len(prop))
                    if prop.attribute_name(i).endswith("Value")
                ]
            elif not group and not members:
                # Preserve the unsupported contract explicitly, rather than dropping it.
                columns = [("attributes", [canonical(self.attributes(prop))])]
            for role, values in columns:
                row["values"] += [
                    tag
                    for i, v in enumerate(values)
                    if (tag := self.tagged(v, role, i)) is not None
                ]
            self.store.put("properties", row)
            self.property_kinds[prop.is_a()] = (
                self.property_kinds.get(prop.is_a(), 0) + 1
            )
            names = {}
            for member in members:
                child_name = getattr(member, "Name", None) or member.is_a()
                ordinal = names.get(child_name, 0)
                names[child_name] = ordinal + 1
                token = child_name.replace("~", "~0").replace("/", "~1")
                visit(
                    member, path + "/" + token + (f"@{ordinal}" if ordinal else ""), pid
                )

        visit(pset, prefix, None, True)

    def metadata(self):
        objects = sorted(
            self.model.by_type("IfcRoot"), key=lambda e: self.identifier(e)
        )
        for number, entity in enumerate(objects, 1):
            if number % 10000 == 0:
                print(f"Metadata: {number:,}/{len(objects):,} IFC roots", flush=True)
            row = {
                "id": self.identifier(entity),
                "model_id": self.model_id,
                "ifc_class": entity.is_a(),
                "global_id": entity.GlobalId,
                "source_step_id": entity.id(),
                "attributes": canonical(self.attributes(entity)),
            }
            is_type = entity.is_a("IfcTypeObject")
            if not is_type:
                assigned = (
                    ifcopenshell.util.element.get_type(entity)
                    if entity.is_a("IfcObject")
                    else None
                )
                row.update(
                    type_id=self.identifier(assigned) if assigned else None,
                    geometry_id=None,
                    transform=None,
                )
            self.store.put("types" if is_type else "entities", row)
            sets = (
                list(getattr(entity, "HasPropertySets", None) or []) if is_type else []
            )
            for rel in getattr(entity, "IsDefinedBy", ()):
                if rel.is_a("IfcRelDefinesByProperties"):
                    value = rel.RelatingPropertyDefinition
                    sets.extend(value if isinstance(value, tuple) else [value])
            for n, pset in enumerate(sets):
                self.property_set(entity, pset, n)
            if entity.is_a("IfcRelationship"):
                # Endpoint lists are represented by endpoint rows. Repeating a full
                # list on every row would turn a group of N members into O(N²) data.
                relationship_attributes = canonical(
                    {
                        key: value
                        for key, value in json.loads(row["attributes"]).items()
                        if not key.startswith(("Relating", "Related"))
                    }
                )
                for i in range(len(entity)):
                    role = entity.attribute_name(i)
                    if not role.startswith(("Relating", "Related")):
                        continue
                    value = entity[i]
                    for n, target in enumerate(
                        value if isinstance(value, tuple) else [value]
                    ):
                        if not isinstance(target, ifcopenshell.entity_instance):
                            continue
                        target_id = self.identifier(target)
                        # Some IFC relationship endpoints are resource entities without GlobalId.
                        if target.id() not in self.root_ids:
                            self.store.put(
                                "entities",
                                {
                                    "id": target_id,
                                    "model_id": self.model_id,
                                    "ifc_class": target.is_a(),
                                    "global_id": None,
                                    "source_step_id": target.id(),
                                    "attributes": canonical(self.attributes(target)),
                                    "type_id": None,
                                    "geometry_id": None,
                                    "transform": None,
                                },
                            )
                        self.store.put(
                            "relations",
                            {
                                "id": str(
                                    uuid.uuid5(uuid.UUID(row["id"]), f"{role}:{n}")
                                ),
                                "model_id": self.model_id,
                                "relationship_id": row["id"],
                                "ifc_class": entity.is_a(),
                                "role": role,
                                "ordinal": n,
                                "target_id": target_id,
                                "attributes": relationship_attributes,
                            },
                        )
        self.store.commit()

    def geometry(self, threads):
        settings = ifcopenshell.geom.settings()
        settings.set("use-world-coords", False)
        products = [
            e
            for e in self.model.by_type("IfcProduct")
            if getattr(e, "Representation", None)
        ]
        iterator = ifcopenshell.geom.iterator(
            settings, self.model, threads, include=products
        )
        cache = {}
        processed = set()
        max_error = 0.0
        if products and iterator.initialize():
            while True:
                shape = iterator.get()
                geometry = shape.geometry
                cache_key = geometry.id
                identifier = cache.get(cache_key)
                if identifier is None:
                    vertices = np.asarray(geometry.verts, dtype=np.float64).reshape(
                        -1, 3
                    )
                    faces = np.asarray(geometry.faces, dtype=np.uint32).reshape(-1, 3)
                    if not np.isfinite(vertices).all():
                        raise ValueError("Non-finite geometry positions")
                    if len(vertices) and len(faces):
                        # Convert IFC Z-up to glTF Y-up, rebase before float32 quantization.
                        vertices = vertices @ C[:3, :3].T
                        origin = (vertices.min(axis=0) + vertices.max(axis=0)) / 2
                        local = vertices - origin
                        positions = np.asarray(local, dtype="<f4")
                        error = float(
                            np.abs(local - positions.astype(np.float64)).max()
                        )
                        max_error = max(max_error, error)
                        materials = []
                        for material in geometry.materials:
                            col = material.diffuse
                            alpha = (
                                1.0 - float(material.transparency)
                                if math.isfinite(material.transparency)
                                else 1.0
                            )
                            materials.append(
                                [float(col.r()), float(col.g()), float(col.b()), alpha]
                            )
                        material_ids = np.asarray(geometry.material_ids, dtype="<i4")
                        meta = {
                            "origin": origin.tolist(),
                            "vertices": len(vertices),
                            "triangles": len(faces),
                            "min": positions.min(axis=0).astype(float).tolist(),
                            "max": positions.max(axis=0).astype(float).tolist(),
                            "materials": materials,
                            "quantization_error_m": error,
                        }
                        p, f, m, metadata = (
                            positions.tobytes(),
                            faces.astype("<u4").tobytes(),
                            material_ids.tobytes(),
                            encoded(meta),
                        )
                        key = hashlib.sha256(p + f + m + metadata).hexdigest()
                        identifier = str(uuid.uuid5(NAMESPACE, "geometry:" + key))
                        self.store.db.execute(
                            "INSERT OR IGNORE INTO meshes VALUES(?,?,?,?,?,?,?)",
                            (
                                identifier,
                                hashlib.sha256(identifier.encode()).hexdigest(),
                                p,
                                f,
                                m,
                                metadata,
                                len(p) + len(f) + len(m) + len(metadata) + 2048,
                            ),
                        )
                        cache[cache_key] = identifier
                if identifier:
                    matrix = np.array(shape.transformation.matrix).reshape(
                        4, 4, order="F"
                    )
                    transform = (C @ matrix @ C.T).flatten(order="F").tolist()
                    self.store.update_geometry(
                        self.identifier(self.model.by_id(shape.id)),
                        identifier,
                        transform,
                    )
                    processed.add(shape.id)
                if len(processed) % 1000 == 0:
                    self.store.commit()
                if not iterator.next():
                    break
        self.store.commit()
        missing = [
            {"id": self.identifier(e), "ifcClass": e.is_a(), "sourceStepId": e.id()}
            for e in products
            if e.id() not in processed
        ]
        return {
            "representedProducts": len(products),
            "meshedProducts": len(processed),
            "uniqueGeometryInSource": len(cache),
            "missingGeometry": missing,
            "maxQuantizationErrorM": max_error,
        }


def extract_file(source, database, threads):
    from .store import Store

    source = Path(source)
    model = ifcopenshell.open(source)
    # Filename is the model namespace; changing file content does not rename every entity.
    model_id = str(uuid.uuid5(NAMESPACE, "model:" + source.name))
    store = Store(database)
    extractor = Extractor(model, model_id, store)
    print(f"Extracting metadata: {source.name}", flush=True)
    extractor.metadata()
    print(f"Tessellating local geometry: {source.name}", flush=True)
    result = extractor.geometry(threads)
    result.update(
        modelId=model_id,
        file=source.name,
        sourceSchema=model.schema,
        sourceSha256=hashlib.file_digest(source.open("rb"), "sha256").hexdigest(),
        sourceBytes=source.stat().st_size,
        propertyKinds=extractor.property_kinds,
        duplicateGlobalIds=len(extractor.duplicate_guids),
        units=[
            extractor.unit(u)
            for project in model.by_type("IfcProject")
            if project.UnitsInContext
            for u in project.UnitsInContext.Units
        ],
    )
    store.close()
    return result
