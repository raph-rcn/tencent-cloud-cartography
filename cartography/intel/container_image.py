from __future__ import annotations


def parse_image_uri(raw: str | None) -> tuple[str | None, str | None]:
    """Return ``(image_uri, image_digest)`` extracted from a raw image reference.

    Handles the image-reference forms returned by AWS ECS and Lambda:

    - ``registry/repo:tag`` — bare tag, no digest.
    - ``registry/repo@sha256:xxx`` — digest pinned, no tag.
    - ``registry/repo:tag@sha256:xxx`` — tag + digest (Lambda's Code.ImageUri
      shape when a tag is used alongside the resolved digest).
    Returns ``(None, None)`` for empty / whitespace-only input. ``image_digest``
    is ``None`` when the reference is not digest-pinned.
    """
    if raw is None:
        return None, None
    uri = raw.strip()
    if not uri:
        return None, None

    digest: str | None = None
    if "@" in uri:
        _, _, digest_candidate = uri.rpartition("@")
        digest = digest_candidate or None

    return uri, digest
