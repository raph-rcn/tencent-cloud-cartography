import re
from urllib.parse import unquote
from xml.etree.ElementTree import fromstring

from cartography.landscape.drawio import ICON_DIRECTORY
from cartography.landscape.drawio import export_drawio


def test_export_drawio_produces_editable_mxfile() -> None:
    # Arrange
    nodes = [
        {
            "id": "account",
            "label": "Example account",
            "type": "account",
            "x": 10,
            "y": 20,
            "width": 400,
            "height": 300,
            "depth": 0,
        },
        {
            "id": "instance",
            "label": "Example instance",
            "type": "resource",
            "icon": "ec2",
            "x": 100,
            "y": 100,
            "width": 58,
            "height": 58,
            "depth": 1,
        },
        {
            "id": "vpc",
            "label": "Example VPC",
            "type": "vpc",
            "x": 40,
            "y": 60,
            "width": 280,
            "height": 220,
            "depth": 1,
        },
        {
            "id": "az",
            "label": "eu-west-1a",
            "type": "availabilityZone",
            "x": 60,
            "y": 80,
            "width": 240,
            "height": 180,
            "depth": 2,
        },
        {
            "id": "subnet",
            "label": "Private subnet · 10.0.0.0/24",
            "type": "subnet",
            "x": 80,
            "y": 100,
            "width": 200,
            "height": 140,
            "depth": 3,
        },
    ]
    edges = []

    # Act
    body = export_drawio(nodes, edges)
    root = fromstring(body)

    # Assert
    assert root.tag == "mxfile"
    cells = root.findall(".//mxCell")
    assert any(cell.attrib.get("id") == "account" for cell in cells)
    instance = next(cell for cell in cells if cell.attrib.get("id") == "instance")
    icon_match = re.search(
        r"image=data:image/svg\+xml,([^;]+);",
        instance.attrib["style"],
    )
    assert icon_match
    assert unquote(icon_match.group(1)) == (ICON_DIRECTORY / "ec2.svg").read_text()
    vpc = next(cell for cell in cells if cell.attrib.get("id") == "vpc")
    assert "grIcon=mxgraph.aws4.group_vpc" in vpc.attrib["style"]
    assert "strokeColor=#8C4FFF" in vpc.attrib["style"]
    az = next(cell for cell in cells if cell.attrib.get("id") == "az")
    assert "strokeColor=#EC7211;dashed=1" in az.attrib["style"]
    subnet = next(cell for cell in cells if cell.attrib.get("id") == "subnet")
    assert "grIcon=mxgraph.aws4.group_security_group" in subnet.attrib["style"]
    assert "strokeColor=#1D8102;fillColor=#E9F3E6" in subnet.attrib["style"]
