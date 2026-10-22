"""The versioned Arrow contract; JSON and GLB are independent payload codecs."""

import json

import pyarrow as pa

PROFILE = "urn:ifcx-oci:profile:0.1"
ARTIFACT_TYPE = "application/vnd.ifcx-oci.model.v0.1"
VALUE = pa.struct(
    [
        ("role", pa.string()),
        ("index", pa.int32()),
        ("ifc_type", pa.string()),
        ("boolean", pa.bool_()),
        ("integer", pa.int64()),
        ("real", pa.float64()),
        ("text", pa.string()),
        ("components_real", pa.list_(pa.field("element", pa.float64()))),
        ("components_integer", pa.list_(pa.field("element", pa.int64()))),
        ("reference", pa.string()),
    ]
)


def schema(fields):
    return pa.schema(
        fields,
        metadata={
            b"ifcx-oci:profile": PROFILE.encode(),
            b"ifcx-oci:attributes": b"canonical JSON object; IFC forward attribute names",
        },
    )


ENTITY_FIELDS = [
    pa.field("id", pa.string(), nullable=False),
    pa.field("model_id", pa.string(), nullable=False),
    pa.field("ifc_class", pa.string(), nullable=False),
    ("global_id", pa.string()),
    pa.field("source_step_id", pa.int64(), nullable=False),
    pa.field("attributes", pa.string(), nullable=False),
]
SCHEMAS = {
    "types": schema(ENTITY_FIELDS),
    "entities": schema(
        ENTITY_FIELDS
        + [
            ("type_id", pa.string()),
            ("geometry_id", pa.string()),
            ("transform", pa.list_(pa.field("element", pa.float64()), 16)),
        ]
    ),
    "properties": schema(
        [
            pa.field("id", pa.string(), nullable=False),
            pa.field("model_id", pa.string(), nullable=False),
            pa.field("owner_id", pa.string(), nullable=False),
            pa.field("owner_kind", pa.string(), nullable=False),
            pa.field("pset_id", pa.string(), nullable=False),
            ("parent_id", pa.string()),
            pa.field("path", pa.string(), nullable=False),
            pa.field("name", pa.string(), nullable=False),
            pa.field("ifc_class", pa.string(), nullable=False),
            pa.field("kind", pa.string(), nullable=False),
            ("description", pa.string()),
            ("usage_name", pa.string()),
            ("unit", pa.string()),
            ("defining_unit", pa.string()),
            ("defined_unit", pa.string()),
            ("expression", pa.string()),
            ("interpolation", pa.string()),
            pa.field("values", pa.list_(pa.field("element", VALUE)), nullable=False),
        ]
    ),
    "relations": schema(
        [
            pa.field("id", pa.string(), nullable=False),
            pa.field("model_id", pa.string(), nullable=False),
            pa.field("relationship_id", pa.string(), nullable=False),
            pa.field("ifc_class", pa.string(), nullable=False),
            pa.field("role", pa.string(), nullable=False),
            pa.field("ordinal", pa.int32(), nullable=False),
            pa.field("target_id", pa.string(), nullable=False),
            pa.field("attributes", pa.string(), nullable=False),
        ]
    ),
    "representations": schema(
        [
            pa.field("id", pa.string(), nullable=False),
            pa.field("blob", pa.string(), nullable=False),
            pa.field("node", pa.int32(), nullable=False),
            pa.field("vertices", pa.int64(), nullable=False),
            pa.field("triangles", pa.int64(), nullable=False),
            pa.field("quantization_error_m", pa.float64(), nullable=False),
        ]
    ),
}


def canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def encoded(value):
    return (canonical(value) + "\n").encode()


def description():
    return {
        "profile": PROFILE,
        "status": "experimental; not a normative buildingSMART IFCX encoding",
        "coordinateSystem": "right-handed, Y-up, metres",
        "transformOrder": "column-major",
        "propertyUnits": "source IFC project units unless an explicit property unit is present",
        "schemas": {
            k: [
                {"name": f.name, "type": str(f.type), "nullable": f.nullable} for f in s
            ]
            for k, s in SCHEMAS.items()
        },
        "attributes": {
            "encoding": "UTF-8 JSON object",
            "keys": "exact IFC forward attribute names",
            "references": {
                "$ref": "exported entity/type ID",
                "$sourceRef": "unmaterialized STEP record in this row's model_id",
            },
            "typedValue": {"$ifcType": "IFC SELECT value type", "value": "JSON value"},
            "null": "explicit absent forward attribute; distinct from missing key",
            "nonFinite": "{$nonFinite: NaN|Infinity|-Infinity}",
            "largeInteger": "{$integer: decimal string} when outside signed int64",
            "canonicalization": "sorted keys, compact separators, UTF-8, no NaN; Python encoder contract",
        },
    }
