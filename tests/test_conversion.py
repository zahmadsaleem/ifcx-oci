import hashlib
import json
import struct

import ifcopenshell
import ifcopenshell.guid
import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from ifcx_oci.contract import canonical
from ifcx_oci.release import convert, file_hash, verify


def fixture(path):
    model = ifcopenshell.file(schema="IFC4")
    guid = ifcopenshell.guid.new
    origin = model.create_entity("IfcCartesianPoint", Coordinates=(0.0, 0.0, 0.0))
    placement = model.create_entity("IfcAxis2Placement3D", Location=origin)
    context = model.create_entity(
        "IfcGeometricRepresentationContext",
        ContextIdentifier="Model",
        ContextType="Model",
        CoordinateSpaceDimension=3,
        Precision=1e-5,
        WorldCoordinateSystem=placement,
    )
    metre = model.create_entity("IfcSIUnit", UnitType="LENGTHUNIT", Name="METRE")
    units = model.create_entity("IfcUnitAssignment", Units=[metre])
    model.create_entity(
        "IfcProject",
        GlobalId=guid(),
        Name="Test",
        RepresentationContexts=[context],
        UnitsInContext=units,
    )
    profile = model.create_entity(
        "IfcRectangleProfileDef", ProfileType="AREA", XDim=2.0, YDim=0.2
    )
    solid = model.create_entity(
        "IfcExtrudedAreaSolid",
        SweptArea=profile,
        Position=placement,
        ExtrudedDirection=model.create_entity(
            "IfcDirection", DirectionRatios=(0.0, 0.0, 1.0)
        ),
        Depth=3.0,
    )
    body = model.create_entity(
        "IfcShapeRepresentation",
        ContextOfItems=context,
        RepresentationIdentifier="Body",
        RepresentationType="SweptSolid",
        Items=[solid],
    )
    shape = model.create_entity("IfcProductDefinitionShape", Representations=[body])
    walls = []
    for x in [0.0, 5.0]:
        point = model.create_entity("IfcCartesianPoint", Coordinates=(x, 0.0, 0.0))
        axis = model.create_entity("IfcAxis2Placement3D", Location=point)
        local = model.create_entity("IfcLocalPlacement", RelativePlacement=axis)
        walls.append(
            model.create_entity(
                "IfcWall",
                GlobalId=guid(),
                Name="Wall",
                Representation=shape,
                ObjectPlacement=local,
            )
        )
    wall_type = model.create_entity(
        "IfcWallType", GlobalId=guid(), Name="Shared", PredefinedType="NOTDEFINED"
    )
    model.create_entity(
        "IfcRelDefinesByType",
        GlobalId=guid(),
        RelatedObjects=walls,
        RelatingType=wall_type,
    )
    zero = model.create_entity(
        "IfcPropertySingleValue",
        Name="Zero",
        NominalValue=model.create_entity("IfcInteger", 0),
    )
    false = model.create_entity(
        "IfcPropertySingleValue",
        Name="False",
        NominalValue=model.create_entity("IfcBoolean", False),
    )
    missing = model.create_entity("IfcPropertySingleValue", Name="Unset")
    complex_prop = model.create_entity(
        "IfcComplexProperty",
        Name="Nested",
        UsageName="Performance",
        HasProperties=[zero, false, missing],
    )
    table = model.create_entity(
        "IfcPropertyTableValue",
        Name="Curve",
        DefiningValues=[
            model.create_entity("IfcFrequencyMeasure", x) for x in [125.0, 250.0]
        ],
        DefinedValues=[model.create_entity("IfcReal", x) for x in [20.0, 35.0]],
        CurveInterpolation="LINEAR",
    )
    bounded = model.create_entity(
        "IfcPropertyBoundedValue",
        Name="Range",
        LowerBoundValue=model.create_entity("IfcLengthMeasure", 1.0),
        UpperBoundValue=model.create_entity("IfcLengthMeasure", 3.0),
        SetPointValue=model.create_entity("IfcLengthMeasure", 2.0),
    )
    pset = model.create_entity(
        "IfcPropertySet",
        GlobalId=guid(),
        Name="Example",
        HasProperties=[complex_prop, table, bounded],
    )
    model.create_entity(
        "IfcRelDefinesByProperties",
        GlobalId=guid(),
        RelatedObjects=walls,
        RelatingPropertyDefinition=pset,
    )
    sequence = model.create_entity(
        "IfcPropertyListValue",
        Name="Sequence",
        ListValues=[model.create_entity("IfcInteger", x) for x in [3, 0, 2]],
    )
    nested_list = model.create_entity(
        "IfcComplexProperty", Name="Core", UsageName="Layer", HasProperties=[sequence]
    )
    layers = model.create_entity(
        "IfcComplexProperty",
        Name="Layers",
        UsageName="Assembly",
        HasProperties=[nested_list],
    )
    complex_number = model.create_entity(
        "IfcPropertySingleValue",
        Name="Impedance",
        NominalValue=model.create_entity("IfcComplexNumber", (1.5, -2.5)),
    )
    enumeration = model.create_entity(
        "IfcPropertyEnumeration",
        Name="Options",
        EnumerationValues=[model.create_entity("IfcLabel", x) for x in ["A", "B"]],
    )
    selected = model.create_entity(
        "IfcPropertyEnumeratedValue",
        Name="Choice",
        EnumerationValues=[model.create_entity("IfcLabel", "B")],
        EnumerationReference=enumeration,
    )
    reference = model.create_entity(
        "IfcPropertyReferenceValue",
        Name="Material",
        PropertyReference=model.create_entity("IfcMaterial", Name="Concrete"),
    )
    pset.HasProperties += (layers, complex_number, selected, reference)
    length = model.create_entity("IfcQuantityLength", Name="Length", LengthValue=2.0)
    complex_quantity = model.create_entity(
        "IfcPhysicalComplexQuantity",
        Name="Dimensions",
        HasQuantities=[length],
        Discrimination="Layer",
        Quality="Nominal",
        Usage="Design",
    )
    quantities = model.create_entity(
        "IfcElementQuantity",
        GlobalId=guid(),
        Name="Quantities",
        Quantities=[complex_quantity],
    )
    model.create_entity(
        "IfcRelDefinesByProperties",
        GlobalId=guid(),
        RelatedObjects=[walls[0]],
        RelatingPropertyDefinition=quantities,
    )
    model.write(path)


def records(root, kind):
    return [
        row
        for p in (root / kind).glob("*.parquet")
        for row in pq.ParquetFile(p).read().to_pylist()
    ]


@pytest.fixture
def converted(tmp_path):
    source = tmp_path / "model.ifc"
    fixture(source)
    output = tmp_path / "release"
    convert(source, output, 64 * 1024, 1)
    return source, output


def test_shared_type_mesh_and_typed_nested_values(converted):
    _, root = converted
    assert verify(root)["valid"]
    walls = [r for r in records(root, "entities") if r["ifc_class"] == "IfcWall"]
    assert len(walls) == 2
    assert len({r["type_id"] for r in walls}) == 1
    assert len({r["geometry_id"] for r in walls}) == 1
    assert walls[0]["transform"] != walls[1]["transform"]
    for row in records(root, "entities"):
        assert canonical(json.loads(row["attributes"])) == row["attributes"]
    props = records(root, "properties")
    nested = next(r for r in props if r["name"] == "Nested")
    children = [r for r in props if r["parent_id"] == nested["id"]]
    assert {r["name"] for r in children} == {"Zero", "False", "Unset"}
    assert next(r for r in children if r["name"] == "Zero")["values"][0]["integer"] == 0
    assert (
        next(r for r in children if r["name"] == "False")["values"][0]["boolean"]
        is False
    )
    assert next(r for r in children if r["name"] == "Unset")["values"] == []
    curve = next(r for r in props if r["name"] == "Curve")
    assert [(v["role"], v["index"]) for v in curve["values"]] == [
        ("defining", 0),
        ("defining", 1),
        ("defined", 0),
        ("defined", 1),
    ]
    assert curve["interpolation"] == "LINEAR"
    bound = next(r for r in props if r["name"] == "Range")
    assert {v["role"]: v["real"] for v in bound["values"]} == {
        "lower": 1.0,
        "upper": 3.0,
        "setPoint": 2.0,
    }


def test_deterministic_release_and_tamper_detection(converted, tmp_path):
    source, first = converted
    second = tmp_path / "second"
    convert(source, second, 64 * 1024, 1)
    assert (first / "index.json").read_bytes() == (second / "index.json").read_bytes()
    file = next((second / "entities").glob("*.parquet"))
    with file.open("ab") as stream:
        stream.write(b"changed")
    with pytest.raises(ValueError, match="integrity"):
        verify(second)


def test_source_reference_attributes_have_an_explicit_tag(converted):
    _, root = converted
    wall = next(r for r in records(root, "entities") if r["ifc_class"] == "IfcWall")
    attributes = json.loads(wall["attributes"])
    assert attributes["Name"] == "Wall"
    assert attributes["ObjectPlacement"]["ifcClass"] == "IfcLocalPlacement"
    assert "$sourceRef" in attributes["ObjectPlacement"]
    for relation in records(root, "relations"):
        assert not any(
            key.startswith(("Relating", "Related"))
            for key in json.loads(relation["attributes"])
        )


def test_glb_dimensions_and_y_up_placement(converted):
    _, root = converted
    path = next((root / "geometry").glob("*.glb"))
    blob = path.read_bytes()
    json_size = struct.unpack_from("<I", blob, 12)[0]
    document = json.loads(blob[20 : 20 + json_size])
    data_start = 28 + json_size
    view = document["bufferViews"][document["accessors"][0]["bufferView"]]
    points = np.frombuffer(
        blob,
        dtype="<f4",
        count=view["byteLength"] // 4,
        offset=data_start + view["byteOffset"],
    ).reshape(-1, 3)
    # A 2m x .2m x 3m IFC wall becomes X=2m, Y=3m, Z=.2m in glTF.
    assert np.allclose(np.ptp(points, axis=0), [2.0, 3.0, 0.2], atol=1e-6)
    walls = [r for r in records(root, "entities") if r["ifc_class"] == "IfcWall"]
    translations = [
        np.array(r["transform"]).reshape(4, 4, order="F")[:3, 3] for r in walls
    ]
    assert np.isclose(np.linalg.norm(translations[0] - translations[1]), 5.0)


def test_complex_numbers_deep_groups_and_quantity_metadata(converted):
    _, root = converted
    rows = records(root, "properties")
    impedance = next(r for r in rows if r["name"] == "Impedance")["values"][0]
    assert impedance["ifc_type"] == "IfcComplexNumber"
    assert impedance["components_real"] == [1.5, -2.5]
    sequence = next(r for r in rows if r["name"] == "Sequence")
    by_id = {r["id"]: r for r in rows}
    core = by_id[sequence["parent_id"]]
    assert core["name"] == "Core"
    assert by_id[core["parent_id"]]["name"] == "Layers"
    assert [v["integer"] for v in sequence["values"]] == [3, 0, 2]
    choice = next(r for r in rows if r["name"] == "Choice")
    assert [(v["role"], v["text"]) for v in choice["values"]] == [
        ("selected", "B"),
        ("allowed", "A"),
        ("allowed", "B"),
    ]
    material = next(r for r in rows if r["name"] == "Material")["values"][0]
    assert json.loads(material["reference"])["ifcClass"] == "IfcMaterial"
    dimensions = next(r for r in rows if r["name"] == "Dimensions")
    assert [dimensions[k] for k in ("discrimination", "quality", "usage")] == [
        "Layer",
        "Nominal",
        "Design",
    ]
    length = next(r for r in rows if r["parent_id"] == dimensions["id"])
    assert length["ifc_class"] == "IfcQuantityLength"
    assert length["values"][0]["real"] == 2.0


def test_resume_replaces_obsolete_shard_files(tmp_path):
    source = tmp_path / "model.ifc"
    fixture(source)
    model = ifcopenshell.open(source)
    for i, wall in enumerate(model.by_type("IfcWall")):
        wall.Description = "".join(
            hashlib.sha256(f"{i}:{n}".encode()).hexdigest() for n in range(4096)
        )
    model.write(source)
    root = tmp_path / "release"
    convert(source, root, 64 * 1024, 1)
    assert len(list((root / "entities").glob("*.parquet"))) > 1
    index = convert(source, root, 8 * 1024**2, 1, resume=True)
    declared = {item["path"] for item in index["files"]}
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*.parquet")}
    assert actual == {p for p in declared if p.endswith(".parquet")}
    assert verify(root)["valid"]


def test_property_reference_must_resolve_even_with_valid_payload_hash(converted):
    _, root = converted
    index = json.loads((root / "index.json").read_bytes())
    item = next(item for item in index["files"] if item["role"] == "properties")
    path = root / item["path"]
    table = pq.read_table(path)
    rows = table.to_pylist()
    row = next(row for row in rows if row["name"] == "Material")
    row["values"][0]["reference"] = canonical({"$ref": "missing-entity"})
    pq.write_table(pa.Table.from_pylist(rows, schema=table.schema), path)
    item.update(size=path.stat().st_size, digest=file_hash(path))
    (root / "index.json").write_text(canonical(index))
    with pytest.raises(ValueError, match="Unresolved owner reference"):
        verify(root)
