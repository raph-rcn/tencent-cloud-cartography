from __future__ import annotations

from datetime import UTC
from datetime import datetime
from functools import lru_cache
from pathlib import Path
import re
from urllib.parse import quote
from xml.etree.ElementTree import Element
from xml.etree.ElementTree import SubElement
from xml.etree.ElementTree import tostring

ICON_DIRECTORY = (
    Path(__file__).resolve().parents[2] / "landscape" / "web" / "public" / "icons"
)
SAFE_ICON_NAME = re.compile(r"^[a-z0-9-]+$")

CONTAINER_STYLES = {
    "account": (
        "shape=mxgraph.aws4.group;grIcon=mxgraph.aws4.group_aws_cloud_alt;"
        "strokeColor=#232F3E;fillColor=none;verticalAlign=top;align=left;"
        "spacingLeft=30;fontColor=#232F3E;html=1;whiteSpace=wrap;"
    ),
    "region": (
        "shape=mxgraph.aws4.group;grIcon=mxgraph.aws4.group_region;"
        "strokeColor=#147EBA;fillColor=none;verticalAlign=top;align=left;"
        "spacingLeft=30;fontColor=#147EBA;html=1;whiteSpace=wrap;"
    ),
    "vpc": (
        "shape=mxgraph.aws4.group;grIcon=mxgraph.aws4.group_vpc;"
        "strokeColor=#8C4FFF;fillColor=none;verticalAlign=top;align=left;"
        "spacingLeft=30;fontColor=#8C4FFF;html=1;whiteSpace=wrap;"
    ),
    "availabilityZone": (
        "fillColor=none;strokeColor=#EC7211;dashed=1;verticalAlign=top;"
        "align=center;fontColor=#B45309;html=1;whiteSpace=wrap;"
    ),
    "subnet": (
        "shape=mxgraph.aws4.group;grIcon=mxgraph.aws4.group_security_group;"
        "grStroke=0;strokeColor=#1D8102;fillColor=#E9F3E6;"
        "verticalAlign=top;align=left;spacingLeft=30;fontColor=#1D8102;"
        "html=1;whiteSpace=wrap;"
    ),
    "type": (
        "fillColor=none;strokeColor=#64748B;dashed=1;verticalAlign=top;"
        "fontColor=#475569;html=1;whiteSpace=wrap;"
    ),
    "component": (
        "fillColor=none;strokeColor=#5A6C86;dashed=1;verticalAlign=top;"
        "fontColor=#5A6C86;html=1;whiteSpace=wrap;fontSize=14;"
    ),
}


@lru_cache
def _icon_data_uri(icon: str) -> str:
    safe_icon = icon if SAFE_ICON_NAME.fullmatch(icon) else "default"
    icon_path = ICON_DIRECTORY / f"{safe_icon}.svg"
    if not icon_path.is_file():
        icon_path = ICON_DIRECTORY / "default.svg"
    return f"data:image/svg+xml,{quote(icon_path.read_text(), safe='')}"


def _resource_style(icon: str) -> str:
    return (
        "shape=image;"
        f"image={_icon_data_uri(icon)};"
        "imageAspect=0;aspect=fixed;"
        "verticalLabelPosition=bottom;verticalAlign=top;align=center;"
        "html=1;aspect=fixed;fontSize=11;"
    )


def export_drawio(nodes: list[dict], edges: list[dict]) -> bytes:
    mxfile = Element(
        "mxfile",
        {
            "host": "app.diagrams.net",
            "modified": datetime.now(UTC).isoformat(),
            "agent": "Cartography Landscape",
            "version": "24.7.17",
            "type": "device",
        },
    )
    diagram = SubElement(
        mxfile, "diagram", {"id": "cartography", "name": "AWS Landscape"}
    )
    model = SubElement(
        diagram,
        "mxGraphModel",
        {
            "dx": "1400",
            "dy": "900",
            "grid": "1",
            "gridSize": "10",
            "page": "1",
            "pageScale": "1",
            "pageWidth": "1654",
            "pageHeight": "1169",
        },
    )
    root = SubElement(model, "root")
    SubElement(root, "mxCell", {"id": "0"})
    SubElement(root, "mxCell", {"id": "1", "parent": "0"})

    for node in sorted(nodes, key=lambda item: item.get("depth", 0)):
        node_type = node.get("type", "resource")
        style = (
            _resource_style(node.get("icon", "default"))
            if node_type == "resource"
            else CONTAINER_STYLES.get(node_type, CONTAINER_STYLES["type"])
        )
        cell = SubElement(
            root,
            "mxCell",
            {
                "id": str(node["id"]),
                "value": str(node.get("label", "")),
                "style": style,
                "vertex": "1",
                "parent": "1",
            },
        )
        SubElement(
            cell,
            "mxGeometry",
            {
                "x": str(round(float(node.get("x", 0)), 2)),
                "y": str(round(float(node.get("y", 0)), 2)),
                "width": str(max(43, round(float(node.get("width", 80)), 2))),
                "height": str(max(43, round(float(node.get("height", 80)), 2))),
                "as": "geometry",
            },
        )

    for edge in edges:
        cell = SubElement(
            root,
            "mxCell",
            {
                "id": str(edge["id"]),
                "value": str(edge.get("label", "")),
                "style": (
                    "edgeStyle=orthogonalEdgeStyle;rounded=1;html=1;"
                    "endArrow=block;endFill=1;strokeColor=#64748B;"
                    "jumpStyle=gap;opacity=80;"
                ),
                "edge": "1",
                "parent": "1",
                "source": str(edge["source"]),
                "target": str(edge["target"]),
            },
        )
        SubElement(cell, "mxGeometry", {"relative": "1", "as": "geometry"})

    return tostring(mxfile, encoding="utf-8", xml_declaration=True)
