"""Multipart uploads: what is actually written on the wire.

A multipart body is assembled by this package rather than by Chromium, so its
shape is this package's responsibility — including the escaping that stops a
crafted filename from writing headers of its own.
"""

import pytest

import cronet
from cronet.request import BOUNDARY_PREFIX, encode_body, encode_multipart

from . import echoed


def _body(options: cronet.RequestOptions) -> tuple[str, str]:
    """The encoded body and its content type, as text for easy assertions."""
    encoded, content_type = encode_body(options)
    assert content_type is not None, "a multipart body always declares its type"
    return encoded.decode("latin-1"), content_type


def test_a_file_is_sent_as_a_part_naming_its_field_and_filename() -> None:
    body, _ = _body({"files": {"photo": ("cat.png", b"\x89PNG")}})

    assert 'Content-Disposition: form-data; name="photo"; filename="cat.png"' in body
    assert "\r\n\r\n\x89PNG\r\n" in body, body


def test_content_given_alone_is_named_after_its_own_field() -> None:
    body, _ = _body({"files": {"upload": b"contents"}})

    assert 'name="upload"; filename="upload"' in body, body


def test_the_media_type_is_guessed_from_the_filename() -> None:
    body, _ = _body({"files": {"page": ("index.html", b"<!doctype html>")}})

    assert "Content-Type: text/html" in body, body


def test_an_unguessable_filename_falls_back_to_octet_stream() -> None:
    body, _ = _body({"files": {"blob": ("mystery.qqq", b"...")}})

    assert "Content-Type: application/octet-stream" in body, body


def test_a_declared_media_type_is_used_as_given() -> None:
    body, _ = _body({"files": {"data": ("thing.txt", b"{}", "application/json")}})

    assert "Content-Type: application/json" in body, body
    assert "text/plain" not in body


def test_text_content_is_encoded_as_utf8() -> None:
    body, _ = _body({"files": {"note": ("note.txt", "héllo")}})

    assert "héllo".encode().decode("latin-1") in body, body


def test_form_fields_travel_as_parts_beside_the_files() -> None:
    body, _ = _body(
        {"form": {"caption": "a cat"}, "files": {"photo": ("cat.png", b"x")}}
    )

    assert 'Content-Disposition: form-data; name="caption"' in body
    assert "\r\n\r\na cat\r\n" in body, body
    assert 'name="photo"' in body


def test_the_content_type_announces_the_boundary_the_body_uses() -> None:
    body, content_type = _body({"files": {"f": b"x"}})

    assert content_type.startswith("multipart/form-data; boundary=")
    boundary = content_type.removeprefix("multipart/form-data; boundary=")
    assert body.startswith(f"--{boundary}\r\n"), body[:80]
    assert body.endswith(f"--{boundary}--\r\n"), body[-80:]


def test_the_boundary_is_shaped_like_chromes() -> None:
    _, content_type = _body({"files": {"f": b"x"}})

    boundary = content_type.removeprefix("multipart/form-data; boundary=")
    assert boundary.startswith(BOUNDARY_PREFIX), boundary
    suffix = boundary.removeprefix(BOUNDARY_PREFIX)
    assert len(suffix) == 16 and suffix.isalnum(), suffix


def test_every_request_gets_its_own_boundary() -> None:
    first = _body({"files": {"f": b"x"}})[1]
    second = _body({"files": {"f": b"x"}})[1]

    assert first != second, "a reused boundary would leak between requests"


def test_a_quote_in_a_filename_cannot_end_the_quoting() -> None:
    body, _ = _body({"files": {"f": ('ev"il.txt', b"x")}})

    assert 'filename="ev%22il.txt"' in body, body


def test_a_newline_in_a_filename_cannot_write_a_header() -> None:
    body, _ = _body({"files": {"f": ("evil.txt\r\nX-Injected: yes", b"x")}})

    # The text survives inside the quoted filename; what it must never do is
    # start a line, which is the only way it would become a header.
    lines = body.split("\r\n\r\n")[0].split("\r\n")
    assert not any(line.startswith("X-Injected") for line in lines), lines
    assert "%0D%0A" in body, body


def test_a_quote_in_a_field_name_cannot_end_the_quoting() -> None:
    body = encode_multipart([('ev"il', "v")], [], "BOUNDARY")

    assert b'name="ev%22il"' in body, body


def test_files_alongside_a_raw_body_is_refused() -> None:
    with pytest.raises(TypeError, match="but not with body"):
        encode_body({"body": b"raw", "files": {"f": b"x"}})


def test_files_alongside_json_is_refused() -> None:
    with pytest.raises(TypeError, match="but not with json"):
        encode_body({"json": {"a": 1}, "files": {"f": b"x"}})


def test_files_may_be_given_in_order_as_pairs() -> None:
    body, _ = _body({"files": [("f", b"one"), ("f", b"two")]})

    assert body.index("one") < body.index("two"), body


def test_an_uploaded_file_reaches_the_server(
    session: cronet.Session, server: str
) -> None:
    response = session.post(
        f"{server}/echo",
        form={"caption": "a cat"},
        files={"photo": ("cat.png", b"\x89PNG\r\n")},
    )

    sent = echoed.request(response)
    headers = echoed.headers(response)
    body = str(sent["body"])
    assert headers["content-type"].startswith("multipart/form-data; boundary=")
    assert 'filename="cat.png"' in body, body
    assert "a cat" in body, body
    # What Chromium announced must match what it actually sent.
    assert headers["content-length"] == str(len(body))
