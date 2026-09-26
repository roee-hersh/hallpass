"""Reading AWS Query-protocol XML the way Go's encoding/xml reads it into
structs: elements matched by local name, namespaces ignored, missing
elements empty. Documents with a DTD are refused, so no entity can expand.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

__all__ = ["XMLError", "child", "children", "parse", "text"]


class XMLError(ValueError):
    pass


def parse(body: bytes, partial: bool = False) -> ET.Element:
    """The root element, read the way xml.Unmarshal reads it: decoding stops
    at the end of the root element, so what follows it is never looked at.

    With partial, a document that breaks off or turns malformed inside the
    root still yields the elements completed before the error, as the
    fields Go had already filled stay filled; XMLError only when no root
    element started at all.
    """
    if b"<!DOCTYPE" in body or b"<!ENTITY" in body:
        # Go ignores a DTD and expands no entity from it; expat would expand
        # internal entities, so a document with a DTD is refused outright.
        raise XMLError("XML with a DTD is not accepted")
    # Go reads character data before the root as a token of its own;
    # expat refuses it, so it is dropped (unless it holds an entity, which
    # Go would reject too).
    lt = body.find(b"<")
    if lt > 0 and b"&" not in body[:lt]:
        body = body[lt:]
    parser = ET.XMLPullParser(events=("start", "end"))
    root: ET.Element | None = None
    try:
        parser.feed(body)
        parser.close()
    except ET.ParseError:
        pass  # the error is also queued after the events that preceded it
    try:
        for ev, el in parser.read_events():
            if ev == "start" and root is None:
                root = el
            elif ev == "end" and el is root:
                return root
    except ET.ParseError as e:
        if partial and root is not None:
            return root
        raise XMLError(f"XML syntax error: {e}") from None
    if partial and root is not None:
        return root
    raise XMLError("XML syntax error: unexpected EOF")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def child(e: ET.Element | None, name: str) -> ET.Element | None:
    """The first direct child with this local name. (Go merges repeated
    elements into one struct; text() with a path does that.)"""
    if e is None:
        return None
    for c in e:
        if _local(c.tag) == name:
            return c
    return None


def children(e: ET.Element | None, name: str) -> list[ET.Element]:
    if e is None:
        return []
    return [c for c in e if _local(c.tag) == name]


def text(e: ET.Element | None, *path: str) -> str:
    """The character data of the element at path under e, or "", as Go
    decodes it into a string field of nested structs: when a name repeats,
    the matches merge and the last one in document order wins; only the
    element's own character data counts, not that of its children."""
    frontier = [e] if e is not None else []
    for p in path:
        frontier = [c for x in frontier for c in children(x, p)]
    if not frontier:
        return ""
    last = frontier[-1]
    return (last.text or "") + "".join(c.tail or "" for c in last)
