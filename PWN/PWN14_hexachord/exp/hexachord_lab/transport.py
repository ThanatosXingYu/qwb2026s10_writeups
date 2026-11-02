"""Byte-preserving menu transport and response framing."""

from __future__ import annotations

from pathlib import Path
import re
import socket
import time

TARGET = re.compile(rb"target:\s*([0-9a-f]{80})")
FRAGMENT = re.compile(rb"(?<![0-9a-f])([0-9a-f]{66})(?![0-9a-f])")
MENU = "6) 离去\n> ".encode()
FULL_MENU = ("1) 调弦\n2) 翻阅琴谱\n3) 开辟共鸣腔\n"
             "4) 弹奏\n5) 哑弦\n6) 离去\n> ").encode()
SCROLL = "卷轴: ".encode()
PRAYER = "祷文: ".encode()
SPELL = "咒文: ".encode()
SUCCESS = "残章到手".encode()

class ProtocolError(Exception):
    pass


class ChapterExpired(ProtocolError):
    def __init__(self, transition: bytes, next_target: str):
        self.transition = transition
        self.next_target = next_target
        super().__init__("chapter expired before exploitation")


class Protocol:
    def __init__(self, sock: socket.socket, transcript: Path):
        self.sock = sock
        self.buffer = bytearray()
        self.log = transcript.open("wb")
        self.rx_log = transcript.with_name("received.bin").open("wb")
        self.tx_log = transcript.with_name("sent.bin").open("wb")

    def close(self) -> None:
        self.log.close()
        self.rx_log.close()
        self.tx_log.close()

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)
        self.tx_log.write(data)
        self.tx_log.flush()
        self.log.write(b"\n<<< TX " + str(len(data)).encode() + b" bytes "
                       + repr(data).encode("ascii") + b"\n")
        self.log.flush()

    def _fill(self, deadline: float) -> None:
        if len(self.buffer) > (1 << 20):
            raise ProtocolError("unmatched response exceeded 1 MiB")
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError(f"response timeout; tail={bytes(self.buffer[-200:])!r}")
        self.sock.settimeout(min(left, 1.0))
        try:
            chunk = self.sock.recv(65536)
        except socket.timeout:
            return
        if not chunk:
            raise EOFError(f"remote closed; tail={bytes(self.buffer[-200:])!r}")
        self.rx_log.write(chunk)
        self.rx_log.flush()
        self.log.write(chunk)
        self.log.flush()
        self.buffer.extend(chunk)

    def until(self, marker: bytes, timeout: float = 20) -> bytes:
        deadline = time.monotonic() + timeout
        while True:
            pos = self.buffer.find(marker)
            if pos >= 0:
                end = pos + len(marker)
                result = bytes(self.buffer[:end])
                del self.buffer[:end]
                return result
            self._fill(deadline)

    def until_pattern(self, pattern: re.Pattern[bytes], timeout: float = 20
                      ) -> tuple[bytes, re.Match[bytes]]:
        deadline = time.monotonic() + timeout
        while True:
            # A match against bytearray shares its storage; deleting the
            # consumed prefix can empty captured groups held by the match.
            match = pattern.search(bytes(self.buffer))
            if match is not None:
                end = match.end()
                result = bytes(self.buffer[:end])
                del self.buffer[:end]
                return result, match
            self._fill(deadline)

    def prompt_or_menu(self, prompt: bytes, timeout: float = 20
                       ) -> tuple[bytes, bool]:
        deadline = time.monotonic() + timeout
        while True:
            found = [(self.buffer.find(x), i, x)
                     for i, x in enumerate((prompt, MENU))]
            found = [entry for entry in found if entry[0] >= 0]
            if found:
                pos, kind, marker = min(found)
                end = pos + len(marker)
                result = bytes(self.buffer[:end])
                del self.buffer[:end]
                return result, kind == 0
            self._fill(deadline)

    def final(self, idle: float = 3, maximum: int = 1 << 20) -> bytes:
        result = bytearray(self.buffer)
        self.buffer.clear()
        deadline = time.monotonic() + idle
        while len(result) < maximum:
            self.sock.settimeout(max(0.1, deadline - time.monotonic()))
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            self.rx_log.write(chunk)
            self.rx_log.flush()
            self.log.write(chunk)
            self.log.flush()
            result.extend(chunk)
            deadline = time.monotonic() + idle
        return bytes(result)


def menu_read(proto: Protocol, path: bytes, timeout: float) -> bytes:
    proto.send(b"2\n")
    proto.until(SCROLL, timeout)
    proto.send(path)
    return SCROLL + proto.until(MENU, timeout)


def menu_tune(proto: Protocol, prayer: bytes, timeout: float) -> bytes:
    if len(prayer) != 112:
        raise ValueError("prayer must be exactly 112 bytes")
    proto.send(b"1\n")
    greeting, prompted = proto.prompt_or_menu(PRAYER, timeout)
    next_match = TARGET.search(greeting)
    if next_match is not None and not prompted:
        raise ChapterExpired(greeting, next_match.group(1).decode("ascii"))
    if not prompted:
        raise ProtocolError(f"menu 1 did not rearm: {greeting[-180:]!r}")
    proto.send(prayer)
    return proto.until(MENU, timeout)


def menu_play(proto: Protocol, spell: bytes, timeout: float) -> bytes:
    if not 1 <= len(spell) <= 31 or b"\n" in spell:
        raise ValueError("spell must be 1..31 bytes without LF")
    proto.send(b"4\n")
    greeting, prompted = proto.prompt_or_menu(SPELL, timeout)
    if not prompted:
        raise ProtocolError(f"menu 4 did not rearm: {greeting[-180:]!r}")
    proto.send(spell + b"\n")
    response = proto.until(MENU, timeout)
    if b"ACCEPT\n" not in response:
        raise ProtocolError(f"checker did not ACCEPT: {response[-240:]!r}")
    return response
