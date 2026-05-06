"""Decoder registry for framed protocol messages.

The registry gives the parser platform a stable extension point without forcing
radar-message assumptions into the CD2 framing layer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from oad_parser.parsers.cd2 import Cd2Frame

DecodedMessage = dict[str, object]
DecoderFunc = Callable[[Cd2Frame], DecodedMessage]


@dataclass(frozen=True)
class DecoderEntry:
    name: str
    description: str
    decode: DecoderFunc


class DecoderRegistry:
    def __init__(self) -> None:
        self._decoders: dict[str, DecoderEntry] = {}

    def register(self, entry: DecoderEntry) -> None:
        if not entry.name:
            raise ValueError("decoder name is required")
        if entry.name in self._decoders:
            raise ValueError(f"decoder already registered: {entry.name}")
        self._decoders[entry.name] = entry

    def names(self) -> list[str]:
        return sorted(self._decoders)

    def get(self, name: str) -> DecoderEntry:
        try:
            return self._decoders[name]
        except KeyError as exc:
            available = ", ".join(self.names()) or "none"
            raise ValueError(f"unknown decoder: {name}; available decoders: {available}") from exc

    def decode(self, name: str, frame: Cd2Frame) -> DecodedMessage:
        return self.get(name).decode(frame)


def build_default_registry() -> DecoderRegistry:
    from oad_parser.decoders.cd2_radar import BEACON_CANDIDATE_DECODER, RAW12_DECODER

    registry = DecoderRegistry()
    registry.register(RAW12_DECODER)
    registry.register(BEACON_CANDIDATE_DECODER)
    return registry
