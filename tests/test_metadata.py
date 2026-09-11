from pathlib import Path

from PIL import Image

from minimal_recon.services.metadata import extract_metadata


def test_extract_metadata_reads_image_dimensions(tmp_path: Path):
    image_path = tmp_path / "sample.png"
    Image.new("RGB", (32, 24), color="red").save(image_path)

    result = extract_metadata(image_path)

    assert result["image_format"] == "PNG"
    assert result["width"] == 32
    assert result["height"] == 24


def test_extract_metadata_handles_non_image_file(tmp_path: Path):
    text_path = tmp_path / "notes.txt"
    text_path.write_text("local evidence", encoding="utf-8")

    result = extract_metadata(text_path)

    assert result["suffix"] == ".txt"
    assert "width" not in result