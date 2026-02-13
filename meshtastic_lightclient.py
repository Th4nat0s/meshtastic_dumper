#!/usr/bin/env python
"""
Meshtastic MQTT client (simulated node listener).
Connects to the public Meshtastic MQTT broker and prints messages.

Allows Channel discovery ( with or without encryption )
Channel dumping with decryption ( when key provided )

Vibecoded with fun by Thanat0s - 2026

GNU Affero 3 Licencing
"""

import argparse
import json
import os
import sys
import time
import base64
import binascii
import struct
from typing import Any, Dict, Optional, Tuple
import re

try:
    import paho.mqtt.client as mqtt
except Exception as exc:  # pragma: no cover - runtime dependency
    print("Missing dependency: paho-mqtt. Install with: pip install paho-mqtt", file=sys.stderr)
    raise

try:
    from meshtastic.protobuf import mesh_pb2
except Exception:
    mesh_pb2 = None
try:
    from meshtastic.protobuf import portnums_pb2
except Exception:
    portnums_pb2 = None
try:
    from meshtastic.protobuf import mqtt_pb2
except Exception:
    mqtt_pb2 = None
try:
    from meshtastic.protobuf import telemetry_pb2
except Exception:
    telemetry_pb2 = None
try:
    from meshtastic.protobuf import neighborinfo_pb2
except Exception:
    neighborinfo_pb2 = None

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except Exception:
    Cipher = None
    algorithms = None
    modes = None

try:
    from google.protobuf.json_format import MessageToDict
except Exception:
    MessageToDict = None

BROKER = os.getenv("MESH_MQTT_HOST", "mqtt.meshtastic.org")
PORT = int(os.getenv("MESH_MQTT_PORT", "1883"))
USERNAME = os.getenv("MESH_MQTT_USER", "meshdev")
PASSWORD = os.getenv("MESH_MQTT_PASS", "large4cats")
TOPIC = os.getenv("MESH_MQTT_TOPIC", "msh/EU_868/#")
CHANNEL_FILTER = os.getenv("MESH_CHANNEL", "LongFast")
CLIENT_ID = os.getenv("MESH_CLIENT_ID", f"lightclient-{int(time.time())}")
SEEN_CHANNELS: set[str] = set()
CHANNEL_STATUS: dict[str, str] = {}
DUMP_FILE: Optional[str] = None

TEXT_PORTNUM = 1
TELEMETRY_PORTNUM = 67
POSITION_PORTNUM = 3
NODEINFO_PORTNUM = 4
ROUTING_PORTNUM = 5
WAYPOINT_PORTNUM = 8
NEIGHBORINFO_PORTNUM = 71
MAP_REPORT_PORTNUM = 73

DEFAULT_CHANNEL_NAMES = {
    "ShortTurbo",
    "ShortSlow",
    "ShortFast",
    "MediumSlow",
    "MediumFast",
    "LongSlow",
    "LongFast",
    "LongTurbo",
    "LongMod",
}

DEFAULT_PSK = bytes(
    [
        0xD4,
        0xF1,
        0xBB,
        0x3A,
        0x20,
        0x29,
        0x07,
        0x59,
        0xF0,
        0xBC,
        0xFF,
        0xAB,
        0xCF,
        0x4E,
        0x69,
        0x01,
    ]
)

USER_KEY: Optional[bytes] = None


def _find_channel_from_topic(topic: str) -> Optional[str]:
    # Prefer robust extraction via /2/e/<CHANNEL>/ or /2/json/<CHANNEL>/.
    chan = _extract_channel_from_topic(topic)
    if chan:
        return chan
    # Backward fallback for legacy simple cases.
    parts = topic.split("/")
    for part in parts:
        if part.lower() == "longfast":
            return "LongFast"
    return None


def _find_channel_from_json(payload: Dict[str, Any]) -> Optional[str]:
    # Try a few likely keys/paths without assuming one schema.
    direct_keys = ["channel", "channel_name", "channelName", "chan", "channelId", "channel_id"]
    for key in direct_keys:
        val = payload.get(key)
        if isinstance(val, str):
            return val

    decoded = payload.get("decoded")
    if isinstance(decoded, dict):
        for key in direct_keys:
            val = decoded.get(key)
            if isinstance(val, str):
                return val

    # Sometimes channel info might be nested under "payload" or "user".
    for subkey in ["payload", "user", "from", "to"]:
        val = payload.get(subkey)
        if isinstance(val, dict):
            for key in direct_keys:
                v2 = val.get(key)
                if isinstance(v2, str):
                    return v2

    return None


def _normalize_channel(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    return str(name).strip()


def _extract_channel_from_topic(topic: str) -> Optional[str]:
    # Try to extract channel from topics like:
    # msh/.../2/e/<CHANNEL>/!node or msh/.../2/json/<CHANNEL>/!node
    parts = topic.split("/")
    for i in range(len(parts) - 2):
        if parts[i] == "2" and parts[i + 1] in ("e", "json"):
            return _normalize_channel(parts[i + 2])
    return None


def _channel_security_label(is_clear: Optional[bool]) -> str:
    if is_clear is None:
        return "Unknown"
    return "Clear" if is_clear else "Ciphered"


def _safe_json(payload_bytes: bytes) -> Optional[Dict[str, Any]]:
    try:
        text = payload_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return None
    if isinstance(obj, dict):
        return obj
    return None


def _format_print(payload: Dict[str, Any], topic: str) -> str:
    # Prefer readable fields if present, otherwise dump compact JSON.
    if isinstance(payload, dict):
        decoded = payload.get("decoded")
        if isinstance(decoded, dict):
            text = decoded.get("payload")
            if isinstance(text, str):
                return f"{topic} :: {text}"
        return f"{topic} :: {json.dumps(payload, ensure_ascii=True)}"
    return f"{topic} :: {payload}"


def _portnum_name(portnum: int) -> Optional[str]:
    if portnums_pb2 is None:
        return None
    try:
        return portnums_pb2.PortNum.Name(int(portnum))
    except Exception:
        return None


def _decode_text_payload(portnum: int, payload: bytes) -> Optional[str]:
    if not payload:
        return None
    if portnum != TEXT_PORTNUM:
        return None
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _decode_telemetry_payload(portnum: int, payload: bytes) -> Optional[Dict[str, Any]]:
    if telemetry_pb2 is None:
        return None
    if portnum != TELEMETRY_PORTNUM or not payload:
        return None
    msg = telemetry_pb2.Telemetry()
    try:
        msg.ParseFromString(payload)
    except Exception:
        return None
    if MessageToDict is not None:
        return MessageToDict(msg, preserving_proto_field_name=True)
    return {"telemetry": str(msg)}


def _decode_proto_message(msg_cls: Any, payload: bytes) -> Optional[Dict[str, Any]]:
    if msg_cls is None or not payload:
        return None
    msg = msg_cls()
    try:
        msg.ParseFromString(payload)
    except Exception:
        return None
    if MessageToDict is not None:
        return MessageToDict(msg, preserving_proto_field_name=True)
    return {"message": str(msg)}


def _decode_generic_payload(portnum: int, payload: bytes) -> Optional[Dict[str, Any]]:
    if portnum == POSITION_PORTNUM:
        return _decode_proto_message(mesh_pb2.Position if mesh_pb2 else None, payload)
    if portnum == NODEINFO_PORTNUM:
        return _decode_proto_message(mesh_pb2.NodeInfo if mesh_pb2 else None, payload)
    if portnum == ROUTING_PORTNUM:
        return _decode_proto_message(mesh_pb2.Routing if mesh_pb2 else None, payload)
    if portnum == WAYPOINT_PORTNUM:
        return _decode_proto_message(mesh_pb2.Waypoint if mesh_pb2 else None, payload)
    if portnum == NEIGHBORINFO_PORTNUM:
        return _decode_proto_message(neighborinfo_pb2.NeighborInfo if neighborinfo_pb2 else None, payload)
    if portnum == MAP_REPORT_PORTNUM:
        return _decode_proto_message(mqtt_pb2.MapReport if mqtt_pb2 else None, payload)
    return None


def _aes_ctr_decrypt(key: bytes, nonce: bytes, data: bytes) -> Optional[bytes]:
    if Cipher is None or algorithms is None or modes is None:
        return None
    if len(nonce) != 16:
        return None
    try:
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()
    except Exception:
        return None


def _decode_data_message(payload: bytes) -> Optional[Dict[str, Any]]:
    if mesh_pb2 is None or not payload:
        return None
    data = mesh_pb2.Data()
    try:
        data.ParseFromString(payload)
    except Exception:
        return None

    portnum = int(getattr(data, "portnum", 0))
    info: Dict[str, Any] = {"portnum": portnum}
    pname = _portnum_name(portnum)
    if pname:
        info["portnum_name"] = pname
    pl = getattr(data, "payload", b"")
    text = _decode_text_payload(portnum, pl)
    if text is not None:
        info["text"] = text
    telemetry = _decode_telemetry_payload(portnum, pl)
    if telemetry is not None:
        info["telemetry"] = telemetry
    generic = _decode_generic_payload(portnum, pl)
    if generic is not None:
        info["decoded_payload"] = generic
    if pl and "text" not in info and "telemetry" not in info and "decoded_payload" not in info:
        info["payload_hex"] = pl.hex()
    return info


def _try_decrypt_default_channel(packet_info: Dict[str, Any], channel_id: Optional[str]) -> Optional[Dict[str, Any]]:
    if not channel_id:
        return None
    channel_id = _normalize_channel(channel_id)
    if channel_id not in DEFAULT_CHANNEL_NAMES:
        return None
    encrypted_hex = packet_info.get("encrypted_hex")
    if not isinstance(encrypted_hex, str):
        return None
    try:
        encrypted = binascii.unhexlify(encrypted_hex)
    except Exception:
        return None
    from_hex = packet_info.get("from")
    pkt_id = packet_info.get("id")
    if not isinstance(from_hex, str) or pkt_id is None:
        return None
    try:
        from_num = int(from_hex, 16)
        pkt_id_num = int(pkt_id)
    except Exception:
        return None

    nonce = struct.pack("<Q", pkt_id_num) + struct.pack("<I", from_num) + b"\x00\x00\x00\x00"
    keys = [DEFAULT_PSK] + [DEFAULT_PSK[:-1] + bytes([(DEFAULT_PSK[-1] + i) & 0xFF]) for i in range(1, 10)]
    for key in keys:
        plain = _aes_ctr_decrypt(key, nonce, encrypted)
        if plain is None:
            continue
        decoded = _decode_data_message(plain)
        if decoded is not None:
            decoded["decrypted"] = True
            return decoded
    return None


def _try_decrypt_with_key(packet_info: Dict[str, Any], key: bytes) -> Optional[Dict[str, Any]]:
    encrypted_hex = packet_info.get("encrypted_hex")
    if not isinstance(encrypted_hex, str):
        return None
    try:
        encrypted = binascii.unhexlify(encrypted_hex)
    except Exception:
        return None
    from_hex = packet_info.get("from")
    pkt_id = packet_info.get("id")
    if not isinstance(from_hex, str) or pkt_id is None:
        return None
    try:
        from_num = int(from_hex, 16)
        pkt_id_num = int(pkt_id)
    except Exception:
        return None

    nonce = struct.pack("<Q", pkt_id_num) + struct.pack("<I", from_num) + b"\x00\x00\x00\x00"
    plain = _aes_ctr_decrypt(key, nonce, encrypted)
    if plain is None:
        return None
    decoded = _decode_data_message(plain)
    if decoded is not None:
        decoded["decrypted"] = True
    return decoded


def _decode_meshpacket(payload_bytes: bytes) -> Optional[Dict[str, Any]]:
    if mesh_pb2 is None:
        return None
    pkt = mesh_pb2.MeshPacket()
    try:
        consumed = pkt.MergeFromString(payload_bytes)
    except Exception:
        return None
    if consumed <= 0:
        return None

    # protobuf uses "from_" in Python because "from" is a keyword
    from_field = getattr(pkt, "from_", None)
    if from_field in (None, 0):
        from_field = getattr(pkt, "from", 0)
    to_field = getattr(pkt, "to", 0)
    info: Dict[str, Any] = {
        "from": f"{from_field:08x}" if from_field else None,
        "to": f"{to_field:08x}" if to_field else None,
        "id": getattr(pkt, "id", None),
        "channel": getattr(pkt, "channel", None),
    }

    if pkt.HasField("decoded"):
        data = pkt.decoded
        portnum = int(getattr(data, "portnum", 0))
        info["portnum"] = portnum
        pname = _portnum_name(portnum)
        if pname:
            info["portnum_name"] = pname
        payload = getattr(data, "payload", b"")
        text = _decode_text_payload(portnum, payload)
        if text is not None:
            info["text"] = text
        telemetry = _decode_telemetry_payload(portnum, payload)
        if telemetry is not None:
            info["telemetry"] = telemetry
        generic = _decode_generic_payload(portnum, payload)
        if generic is not None:
            info["decoded_payload"] = generic
        if payload and "text" not in info and "telemetry" not in info and "decoded_payload" not in info:
            info["payload_hex"] = payload.hex()
    else:
        encrypted = getattr(pkt, "encrypted", b"")
        if encrypted:
            info["encrypted_hex"] = encrypted.hex()

    if consumed < len(payload_bytes):
        info["trailing_hex"] = payload_bytes[consumed:].hex()
    return info


def _decode_service_envelope(payload_bytes: bytes) -> Optional[Dict[str, Any]]:
    if mqtt_pb2 is None:
        return None
    env = mqtt_pb2.ServiceEnvelope()
    try:
        consumed = env.MergeFromString(payload_bytes)
    except Exception:
        return None
    if consumed <= 0:
        return None

    info: Dict[str, Any] = {}
    if getattr(env, "channel_id", None):
        info["channel_id"] = env.channel_id
    if getattr(env, "gateway_id", None):
        info["gateway_id"] = env.gateway_id
    if getattr(env, "packet", None):
        pkt_bytes = env.packet.SerializeToString()
        pkt_info = _decode_meshpacket(pkt_bytes)
        if pkt_info is not None:
            info["packet"] = pkt_info
    # Try decrypting encrypted payloads for default channels.
    if "packet" in info and isinstance(info.get("channel_id"), str):
        pkt = info["packet"]
        if isinstance(pkt, dict) and "encrypted_hex" in pkt and "text" not in pkt:
            decrypted = None
            if USER_KEY:
                decrypted = _try_decrypt_with_key(pkt, USER_KEY)
            if decrypted is None:
                decrypted = _try_decrypt_default_channel(pkt, info.get("channel_id"))
            if decrypted is not None:
                pkt.update(decrypted)
    if consumed < len(payload_bytes):
        info["trailing_hex"] = payload_bytes[consumed:].hex()
    return info


def _maybe_decode_ascii_payload(payload_bytes: bytes) -> Tuple[bytes, bool]:
    # Some MQTT bridges publish hex/base64 payloads as ASCII. Detect and decode.
    try:
        s = payload_bytes.decode("ascii")
    except Exception:
        return payload_bytes, False
    if len(s) % 2 != 0:
        # Might still be base64, continue.
        pass
    if all(c in "0123456789abcdefABCDEF" for c in s) and len(s) % 2 == 0:
        try:
            return binascii.unhexlify(s), True
        except Exception:
            pass
    # Try base64
    if all(c.isalnum() or c in "+/=" for c in s):
        try:
            return base64.b64decode(s, validate=True), True
        except Exception:
            pass
    return payload_bytes, False


def _summarize_text(topic: str, sender: str, text: str) -> str:
    return f"{topic} :: from=!{sender} text={text}"


def _summarize_telemetry(topic: str, sender: str, telemetry: Dict[str, Any]) -> str:
    return f"{topic} :: from=!{sender} telemetry={json.dumps(telemetry, ensure_ascii=True)}"


def _emit(line: str) -> None:
    print(line)
    if DUMP_FILE:
        try:
            with open(DUMP_FILE, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass


def _extract_ascii_strings(payload_bytes: bytes, min_len: int = 4) -> list[str]:
    try:
        text = payload_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return []
    # Keep simple printable runs
    return [s for s in re.findall(r"[ -~]{%d,}" % min_len, text) if s.strip()]


def on_connect(client: mqtt.Client, userdata: Any, flags: Dict[str, Any], rc: int) -> None:
    if rc == 0:
        print(f"Connected to {BROKER}:{PORT} as {CLIENT_ID}")
        client.subscribe(TOPIC)
        print(f"Subscribed to {TOPIC}, filtering channel: {CHANNEL_FILTER}")
    else:
        print(f"Connection failed: rc={rc}")


def on_message(client: mqtt.Client, userdata: Any, msg: mqtt.MQTTMessage) -> None:
    topic = msg.topic
    payload_bytes, was_hex = _maybe_decode_ascii_payload(msg.payload)
    channel = _find_channel_from_topic(topic)
    payload_json = _safe_json(payload_bytes)
    if payload_json is not None:
        ch = _find_channel_from_json(payload_json)
        if ch:
            channel = ch
        if ARGS.sneakchannel:
            # Prefer explicit channel_id in JSON, fallback to topic parsing.
            chan = payload_json.get("channel_id")
            if isinstance(chan, str):
                chan = _normalize_channel(chan)
            if not chan:
                chan = _extract_channel_from_topic(topic)
            # Determine encryption status if possible.
            is_clear: Optional[bool] = None
            pkt = payload_json.get("packet")
            if isinstance(pkt, dict):
                if "decoded" in pkt or "payload" in pkt or "text" in pkt:
                    is_clear = True
                elif "encrypted_hex" in pkt:
                    # Try default-key decrypt for default channels
                    if USER_KEY and _try_decrypt_with_key(pkt, USER_KEY) is not None:
                        is_clear = True
                    elif chan and _try_decrypt_default_channel(pkt, chan) is not None:
                        is_clear = True
                    else:
                        is_clear = False
            if chan:
                label = _channel_security_label(is_clear)
                prev = CHANNEL_STATUS.get(chan)
                if prev is None:
                    CHANNEL_STATUS[chan] = label
                    SEEN_CHANNELS.add(chan)
                    _emit(f"{chan} {label}")
                elif prev == "Unknown" and label in ("Clear", "Ciphered"):
                    CHANNEL_STATUS[chan] = label
                    _emit(f"{chan} {label}")
            return

    if ARGS.sneakchannel:
        # Non-JSON payloads: try protobuf decode for channel_id + encryption status.
        decoded_env = _decode_service_envelope(payload_bytes)
        chan = None
        is_clear: Optional[bool] = None
        if decoded_env is not None:
            if isinstance(decoded_env.get("channel_id"), str):
                chan = _normalize_channel(decoded_env.get("channel_id"))
            if chan is None:
                chan = _extract_channel_from_topic(topic)
            pkt = decoded_env.get("packet")
            if isinstance(pkt, dict):
                if "text" in pkt or "decoded_payload" in pkt:
                    is_clear = True
                elif "encrypted_hex" in pkt:
                    if USER_KEY and _try_decrypt_with_key(pkt, USER_KEY) is not None:
                        is_clear = True
                    elif chan and _try_decrypt_default_channel(pkt, chan) is not None:
                        is_clear = True
                    else:
                        is_clear = False
        else:
            chan = _extract_channel_from_topic(topic)
        if chan:
            label = _channel_security_label(is_clear)
            prev = CHANNEL_STATUS.get(chan)
            if prev is None:
                CHANNEL_STATUS[chan] = label
                SEEN_CHANNELS.add(chan)
                _emit(f"{chan} {label}")
            elif prev == "Unknown" and label in ("Clear", "Ciphered"):
                CHANNEL_STATUS[chan] = label
                _emit(f"{chan} {label}")
        return

    if CHANNEL_FILTER != "#" and channel != CHANNEL_FILTER:
        return

    if payload_json is not None:
        msg_type = payload_json.get("type")
        payload_obj = payload_json.get("payload")
        text = None
        if msg_type == "text":
            if isinstance(payload_obj, dict) and "text" in payload_obj:
                text = payload_obj.get("text")
            elif isinstance(payload_obj, str):
                text = payload_obj
            elif payload_obj is not None:
                text = json.dumps(payload_obj, ensure_ascii=True)
        if ARGS.show_all:
            _emit(_format_print(payload_json, topic))
        if ARGS.show_text and isinstance(text, str) and text:
            sender = payload_json.get("sender") or payload_json.get("from") or "unknown"
            _emit(_summarize_text(topic, str(sender).lstrip("!"), text))
        if ARGS.show_telemetry and msg_type == "telemetry":
            _emit(_summarize_telemetry(topic, payload_json.get("sender", "unknown"), payload_json))
        return

    decoded_env = _decode_service_envelope(payload_bytes)
    decoded = None
    if decoded_env is not None:
        decoded = decoded_env.get("packet") or {}
    if decoded is None or decoded == {}:
        decoded = _decode_meshpacket(payload_bytes)

    if decoded is None:
        if ARGS.show_all:
            strings = _extract_ascii_strings(payload_bytes)
            if strings:
                _emit(f"{topic} :: strings={strings}")
        elif ARGS.show_failed:
            hint = "hex-payload" if was_hex else "raw-bytes"
            _emit(f"{topic} :: decode_failed ({hint})")
        if ARGS.dump_failed:
            try:
                with open(ARGS.dump_failed, "a", encoding="ascii") as f:
                    f.write(f"{topic} :: {payload_bytes.hex()}\n")
            except Exception:
                pass
        return

    sender = decoded.get("from") or (decoded_env.get("gateway_id") if decoded_env else None) or "unknown"
    text = decoded.get("text")
    telemetry = decoded.get("telemetry")

    if ARGS.show_all:
        _emit(f"{topic} :: {json.dumps(decoded_env or decoded, ensure_ascii=True)}")

    if ARGS.show_text and isinstance(text, str) and text:
        _emit(_summarize_text(topic, sender, text))

    if ARGS.show_telemetry and isinstance(telemetry, dict):
        _emit(_summarize_telemetry(topic, sender, telemetry))


def main() -> int:
    global ARGS
    parser = argparse.ArgumentParser(description="Meshtastic MQTT light client listener")
    parser.add_argument("--telemetry", dest="show_telemetry", action="store_true", help="Print telemetry messages")
    parser.add_argument("--text", dest="show_text", action="store_true", help="Print text messages")
    parser.add_argument("--all", dest="show_all", action="store_true", help="Print all protocol details")
    parser.add_argument("--decode-hex", metavar="HEX", help="Decode a single hex payload and exit")
    parser.add_argument("--decode-json", metavar="JSON", help="Decode a JSON payload line and exit")
    parser.add_argument("--dump-failed", metavar="FILE", help="Append undecoded payloads as hex to FILE")
    parser.add_argument("--show-failed", action="store_true", help="Print decode_failed lines")
    parser.add_argument("--subscribe", metavar="CHANNEL", help="Channel filter (default LongFast). Use # for all.")
    parser.add_argument("--sneakchannel", action="store_true", help="Listen to all and print each channel_id once")
    parser.add_argument("--dump", metavar="FILE", help="Append output lines to FILE")
    parser.add_argument("--key", metavar="BASE64", help="Base64 PSK for decrypting encrypted payloads")
    parser.add_argument("--channel-id", metavar="ID", help="Channel ID to use with --decode-hex")
    ARGS = parser.parse_args()
    if ARGS.key:
        if Cipher is None:
            print("Error: cryptography is required for --key. Install: pip install cryptography", file=sys.stderr)
            return 2
        try:
            key_bytes = base64.b64decode(ARGS.key.strip())
        except Exception:
            print("Error: invalid base64 key", file=sys.stderr)
            return 2
        if len(key_bytes) not in (16, 32):
            print("Error: key must be 16 or 32 bytes", file=sys.stderr)
            return 2
        global USER_KEY
        USER_KEY = key_bytes
    if ARGS.dump:
        global DUMP_FILE
        DUMP_FILE = ARGS.dump
    if ARGS.decode_hex:
        if mesh_pb2 is None or mqtt_pb2 is None:
            print("Error: meshtastic protobufs not available. Install: pip install meshtastic protobuf", file=sys.stderr)
            return 2
        try:
            payload_bytes = binascii.unhexlify(ARGS.decode_hex.strip())
        except Exception:
            print("Error: invalid hex string", file=sys.stderr)
            return 2
        decoded_env = _decode_service_envelope(payload_bytes)
        if decoded_env is not None:
            if ARGS.channel_id and "packet" in decoded_env and isinstance(decoded_env.get("packet"), dict):
                pkt = decoded_env["packet"]
                if USER_KEY and "encrypted_hex" in pkt:
                    decrypted = _try_decrypt_with_key(pkt, USER_KEY)
                    if decrypted is not None:
                        pkt.update(decrypted)
            print(json.dumps(decoded_env, ensure_ascii=True))
            return 0
        decoded = _decode_meshpacket(payload_bytes)
        if decoded is not None:
            print(json.dumps(decoded, ensure_ascii=True))
            return 0
        print("Error: decode failed", file=sys.stderr)
        return 2
    if ARGS.decode_json:
        if mesh_pb2 is None or mqtt_pb2 is None:
            print("Error: meshtastic protobufs not available. Install: pip install meshtastic protobuf", file=sys.stderr)
            return 2
        try:
            obj = json.loads(ARGS.decode_json)
        except Exception:
            print("Error: invalid JSON", file=sys.stderr)
            return 2
        if not isinstance(obj, dict):
            print("Error: JSON must be an object", file=sys.stderr)
            return 2
        pkt = obj.get("packet")
        if USER_KEY and isinstance(pkt, dict) and "encrypted_hex" in pkt:
            decrypted = _try_decrypt_with_key(pkt, USER_KEY)
            if decrypted is not None:
                pkt.update(decrypted)
        print(json.dumps(obj, ensure_ascii=True))
        return 0
    if not (ARGS.show_all or ARGS.show_text or ARGS.show_telemetry):
        # If user only provided non-output options (e.g. --subscribe), default to --text.
        if ARGS.subscribe or ARGS.dump_failed or ARGS.show_failed or ARGS.sneakchannel:
            ARGS.show_text = True
        else:
            parser.print_help()
            return 0
    if ARGS.subscribe:
        global CHANNEL_FILTER
        CHANNEL_FILTER = ARGS.subscribe
    if ARGS.sneakchannel:
        CHANNEL_FILTER = "#"
    if mesh_pb2 is None or mqtt_pb2 is None:
        print("Error: meshtastic protobufs not available. Install: pip install meshtastic protobuf", file=sys.stderr)
        return 2
    if ARGS.show_telemetry and telemetry_pb2 is None:
        print("Error: telemetry protobufs unavailable. Install: pip install meshtastic protobuf", file=sys.stderr)
        return 2

    client = mqtt.Client(client_id=CLIENT_ID, clean_session=True)
    client.username_pw_set(USERNAME, PASSWORD)
    client.on_connect = on_connect
    client.on_message = on_message

    client.connect(BROKER, PORT, keepalive=60)
    client.loop_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
