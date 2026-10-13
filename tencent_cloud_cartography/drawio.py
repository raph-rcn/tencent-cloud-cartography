"""Editable diagrams.net documents with embedded official Tencent SVGs."""

import base64
import math
from xml.etree import ElementTree as ET

from .icons import icon_bytes


def export(payload):
    nodes, edges = payload["nodes"], payload["edges"]
    if (
        not isinstance(nodes, list)
        or not isinstance(edges, list)
        or len(nodes) > 12000
        or len(edges) > 50000
    ):
        raise ValueError("Diagram too large")
    ids = [str(n["id"]) for n in nodes]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate node IDs")
    by_id = {str(n["id"]): n for n in nodes}
    mapped = {nid: "n" + str(i) for i, nid in enumerate(ids)}
    root = ET.Element("mxfile", host="Tencent Cloud Cartography")
    diagram = ET.SubElement(root, "diagram", name="Tencent Cloud")
    model = ET.SubElement(diagram, "mxGraphModel", grid="1", page="0")
    cells = ET.SubElement(model, "root")
    ET.SubElement(cells, "mxCell", id="0")
    ET.SubElement(cells, "mxCell", id="1", parent="0")
    for n in nodes:
        nid = str(n["id"])
        ancestor, visited = n.get("parent"), {nid}
        while ancestor in by_id:
            if ancestor in visited:
                raise ValueError("Cyclic diagram containment")
            visited.add(ancestor)
            ancestor = by_id[ancestor].get("parent")
        values = [
            float(n.get(k, d)) for k, d in [("x", 0), ("y", 0), ("width", 100), ("height", 100)]
        ]
        if any(not math.isfinite(v) or abs(v) > 10_000_000 for v in values) or min(values[2:]) <= 0:
            raise ValueError("Invalid diagram geometry")
        x, y, w, h = values
        parent = n.get("parent")
        if parent in by_id:
            x -= float(by_id[parent].get("x", 0))
            y -= float(by_id[parent].get("y", 0))
        style = "rounded=1;fillColor=none;strokeColor=#0052d9;verticalAlign=top;align=left;spacing=10;whiteSpace=wrap;html=0;"
        if n.get("type") == "resource":
            svg = base64.b64encode(icon_bytes(n.get("icon"))).decode()
            style = (
                "shape=image;image=data:image/svg+xml,"
                + svg
                + ";imageAspect=1;verticalLabelPosition=bottom;verticalAlign=top;whiteSpace=wrap;html=0;"
            )
        cell = ET.SubElement(
            cells,
            "mxCell",
            id=mapped[nid],
            value=str(n.get("label", nid)),
            style=style,
            vertex="1",
            parent=mapped.get(parent, "1"),
        )
        ET.SubElement(
            cell,
            "mxGeometry",
            {"x": str(x), "y": str(y), "width": str(w), "height": str(h), "as": "geometry"},
        )
    for i, edge in enumerate(edges):
        if edge["source"] not in mapped or edge["target"] not in mapped:
            raise ValueError("Unknown edge endpoint")
        cell = ET.SubElement(
            cells,
            "mxCell",
            id="e" + str(i),
            value=str(edge.get("label", "")),
            style="edgeStyle=orthogonalEdgeStyle;rounded=1;endArrow=block;strokeColor=#52647a;html=0;",
            edge="1",
            parent="1",
            source=mapped[edge["source"]],
            target=mapped[edge["target"]],
        )
        ET.SubElement(cell, "mxGeometry", {"relative": "1", "as": "geometry"})
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)
