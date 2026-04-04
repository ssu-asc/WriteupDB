#!/usr/bin/env python3

import argparse
import os
import posixpath
import xml.etree.ElementTree as ET
import zipfile


P_NS = "http://schemas.openxmlformats.org/presentationml/2006/main"
R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKG_NS = "http://schemas.openxmlformats.org/package/2006/relationships"

IMAGE_TO_SYMBOL = {
    "image2.png": "6",
    "image3.png": "7",
    "image4.jpg": "_",
}


def read_xml(zip_file: zipfile.ZipFile, name: str) -> ET.Element:
    return ET.fromstring(zip_file.read(name))


def get_slide_order(zip_file: zipfile.ZipFile) -> list[str]:
    presentation = read_xml(zip_file, "ppt/presentation.xml")
    rels = read_xml(zip_file, "ppt/_rels/presentation.xml.rels")

    rel_map = {
        rel.attrib["Id"]: rel.attrib["Target"]
        for rel in rels.findall(f"{{{PKG_NS}}}Relationship")
    }

    ordered = []
    slide_id_list = presentation.find(f"{{{P_NS}}}sldIdLst")
    if slide_id_list is None:
        raise ValueError("slide list not found")

    for slide in slide_id_list.findall(f"{{{P_NS}}}sldId"):
        rel_id = slide.attrib[f"{{{R_NS}}}id"]
        ordered.append(posixpath.normpath(posixpath.join("ppt", rel_map[rel_id])))
    return ordered


def get_image_name_for_slide(zip_file: zipfile.ZipFile, slide_path: str) -> str:
    slide_dir = posixpath.dirname(slide_path)
    rel_name = posixpath.join(
        slide_dir,
        "_rels",
        posixpath.basename(slide_path) + ".rels",
    )
    rels = read_xml(zip_file, rel_name)

    for rel in rels.findall(f"{{{PKG_NS}}}Relationship"):
        if rel.attrib.get("Type", "").endswith("/image"):
            target = rel.attrib["Target"]
            return os.path.basename(posixpath.normpath(posixpath.join(slide_dir, target)))

    raise ValueError(f"image relationship not found for {slide_path}")


def decode_flag(pptx_path: str) -> str:
    with zipfile.ZipFile(pptx_path) as zip_file:
        sequence = []
        for slide_path in get_slide_order(zip_file):
            image_name = get_image_name_for_slide(zip_file, slide_path)
            try:
                sequence.append(IMAGE_TO_SYMBOL[image_name])
            except KeyError as exc:
                raise ValueError(f"unexpected image: {image_name}") from exc

    bytes_as_symbols = "".join(sequence).split("_")
    bits = ["".join("0" if char == "6" else "1" for char in chunk) for chunk in bytes_as_symbols]
    values = [int(bit_string, 2) for bit_string in bits if bit_string]
    return "".join(chr(value) for value in values)


def main() -> None:
    parser = argparse.ArgumentParser(description="Decode the six-to-seven PPTX challenge.")
    parser.add_argument("pptx", nargs="?", default="sixtotheseven.pptx")
    args = parser.parse_args()

    print(decode_flag(args.pptx))


if __name__ == "__main__":
    main()
