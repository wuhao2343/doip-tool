#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
交互式 DoIP + UDS 诊断脚本

用法示例：
  discover
  ip 192.168.0.10
  source 0x0E00
  target 0x1234
  connect
  10 03
  22 F1 90
  19 02 FF
"""

import socket
import struct
import sys
import threading
import time

# ============================================================
# 常用配置：一般优先改这里
# ============================================================

# 车辆 DoIP 节点 IP。
# 如果不知道，可以先保持 None，进入控制台后执行 discover。
# 如果已经知道车端 IP，可以写成 "192.168.0.10"。
VEHICLE_IP = None

# 本机绑定 IP。
# 多网卡电脑建议指定诊断网卡 IP，例如 "192.168.0.100"。
# 不确定时保持 "0.0.0.0"。
LOCAL_BIND_IP = "0.0.0.0"

# 诊断仪 Tester 逻辑地址。
TESTER_LOGICAL_ADDRESS = 0x0E00

# 目标 ECU 逻辑地址
TARGET_LOGICAL_ADDRESS = 0x0001

# Routing Activation 类型。
# 常见：
#   0x00：默认诊断
#   0x01：WWH-OBD
#   0xE0-0xFF：车厂自定义
ROUTING_ACTIVATION_TYPE = 0x00

# DoIP 协议版本。
# 常见：
#   0x02：ISO 13400-2:2012 常见
#   0x03：ISO 13400-2:2019 某些平台使用
DOIP_PROTOCOL_VERSION = 0x02

# DoIP TCP/UDP 端口，标准端口通常都是 13400。
DOIP_TCP_PORT = 13400
DOIP_UDP_PORT = 13400

# UDP 发现广播地址。
# 如果全局广播搜不到，可以改成指定网段广播，例如 "192.168.0.255"。
DISCOVERY_BROADCAST_IP = "255.255.255.255"

# ============================================================
# 不常用配置：特殊车辆平台或调试时再改
# ============================================================

# 本机 TCP 源端口。0 表示系统自动分配。
LOCAL_TCP_SOURCE_PORT = 0

# Routing Activation OEM 自定义数据。
# 大多数车辆为空，少数车厂可能要求额外认证或激活数据。
ROUTING_ACTIVATION_OEM_DATA = b""

# TCP 连接超时时间，单位秒。
TCP_CONNECT_TIMEOUT = 5.0

# TCP 接收超时时间，单位秒。
TCP_RECV_TIMEOUT = 2.0

# UDP 车辆发现等待时间，单位秒。
DISCOVERY_TIMEOUT = 3.0

# 普通 UDS 响应等待时间，单位秒。
UDS_RESPONSE_TIMEOUT = 5.0

# ECU 返回 0x78 ResponsePending 后，最多继续等待多久。
UDS_RESPONSE_PENDING_MAX_WAIT = 15.0

# TesterPresent 保活周期，单位秒。
TESTER_PRESENT_INTERVAL = 2.0

# connect 后是否自动执行 Routing Activation。
AUTO_ROUTING_ACTIVATION = True

# 发送 UDS 前如果还没连接，是否自动连接。
AUTO_CONNECT_BEFORE_UDS = True

# 是否打印 DoIP 原始报文。
PRINT_DOIP_RAW = True

# 是否打印 UDS 层解释。
PRINT_UDS_INFO = True

# ============================================================
# DoIP Payload Type
# ============================================================

PT_GENERIC_NACK = 0x0000
PT_VEHICLE_IDENTIFICATION_REQUEST = 0x0001
PT_VEHICLE_ANNOUNCEMENT = 0x0004
PT_ROUTING_ACTIVATION_REQUEST = 0x0005
PT_ROUTING_ACTIVATION_RESPONSE = 0x0006
PT_ALIVE_CHECK_REQUEST = 0x0007
PT_ALIVE_CHECK_RESPONSE = 0x0008
PT_DIAGNOSTIC_MESSAGE = 0x8001
PT_DIAGNOSTIC_MESSAGE_POSITIVE_ACK = 0x8002
PT_DIAGNOSTIC_MESSAGE_NEGATIVE_ACK = 0x8003


def hex_bytes(data: bytes) -> str:
    return data.hex(" ").upper()


def parse_hex_string(text: str) -> bytes:
    cleaned = (
        text.replace("0x", "")
        .replace("0X", "")
        .replace(",", " ")
        .replace(";", " ")
        .replace("-", " ")
        .replace("_", " ")
    )
    parts = cleaned.split()

    if not parts:
        raise ValueError("请输入十六进制数据")

    if len(parts) == 1 and len(parts[0]) > 2:
        raw = parts[0]
        if len(raw) % 2 != 0:
            raise ValueError("十六进制字符串长度必须是偶数")
        return bytes.fromhex(raw)

    return bytes(int(part, 16) for part in parts)


def parse_int(text: str) -> int:
    return int(text, 16) if text.lower().startswith("0x") else int(text, 16)


def u16(value: int) -> bytes:
    return struct.pack(">H", value & 0xFFFF)


def build_doip_header(payload_type: int, payload_length: int) -> bytes:
    version = DOIP_PROTOCOL_VERSION
    inverse = version ^ 0xFF
    return struct.pack(">BBHI", version, inverse, payload_type, payload_length)


def build_doip_message(payload_type: int, payload: bytes = b"") -> bytes:
    return build_doip_header(payload_type, len(payload)) + payload


def parse_doip_header(header: bytes):
    if len(header) != 8:
        raise ValueError("DoIP header 长度必须是 8 字节")

    version, inverse, payload_type, payload_length = struct.unpack(">BBHI", header)

    if (version ^ inverse) != 0xFF:
        raise ValueError(
            f"DoIP 版本校验失败: version=0x{version:02X}, inverse=0x{inverse:02X}"
        )

    return version, payload_type, payload_length


def uds_service_name(service_id: int) -> str:
    names = {
        0x10: "DiagnosticSessionControl",
        0x11: "ECUReset",
        0x14: "ClearDiagnosticInformation",
        0x19: "ReadDTCInformation",
        0x22: "ReadDataByIdentifier",
        0x27: "SecurityAccess",
        0x2E: "WriteDataByIdentifier",
        0x31: "RoutineControl",
        0x34: "RequestDownload",
        0x36: "TransferData",
        0x37: "RequestTransferExit",
        0x3E: "TesterPresent",
        0x85: "ControlDTCSetting",
    }
    return names.get(service_id, "Unknown")


def uds_nrc_name(nrc: int) -> str:
    names = {
        0x10: "GeneralReject",
        0x11: "ServiceNotSupported",
        0x12: "SubFunctionNotSupported",
        0x13: "IncorrectMessageLengthOrInvalidFormat",
        0x22: "ConditionsNotCorrect",
        0x24: "RequestSequenceError",
        0x31: "RequestOutOfRange",
        0x33: "SecurityAccessDenied",
        0x35: "InvalidKey",
        0x36: "ExceedNumberOfAttempts",
        0x37: "RequiredTimeDelayNotExpired",
        0x78: "ResponsePending",
        0x7E: "SubFunctionNotSupportedInActiveSession",
        0x7F: "ServiceNotSupportedInActiveSession",
    }
    return names.get(nrc, "UnknownNRC")


def print_uds_info(uds: bytes):
    if not PRINT_UDS_INFO or not uds:
        return

    if uds[0] == 0x7F and len(uds) >= 3:
        req_sid = uds[1]
        nrc = uds[2]
        print(
            f"UDS NRC: request_sid=0x{req_sid:02X} "
            f"({uds_service_name(req_sid)}), "
            f"nrc=0x{nrc:02X} ({uds_nrc_name(nrc)})"
        )
        return

    if uds[0] >= 0x40:
        req_sid = uds[0] - 0x40
        print(
            f"UDS Positive: response_sid=0x{uds[0]:02X}, "
            f"request_sid=0x{req_sid:02X} ({uds_service_name(req_sid)})"
        )
    else:
        print(f"UDS: sid=0x{uds[0]:02X} ({uds_service_name(uds[0])})")


class DoIPClient:
    def __init__(self):
        self.vehicle_ip = VEHICLE_IP
        self.tester_addr = TESTER_LOGICAL_ADDRESS
        self.target_addr = TARGET_LOGICAL_ADDRESS
        self.sock = None
        self.routing_activated = False
        self.discovered_entity_addr = None
        self.routing_entity_addr = None
        self.tester_present_running = False
        self.tester_present_thread = None

    def discover(self):
        msg = build_doip_message(PT_VEHICLE_IDENTIFICATION_REQUEST)

        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        udp.settimeout(DISCOVERY_TIMEOUT)

        try:
            udp.bind((LOCAL_BIND_IP, 0))
        except OSError as exc:
            print(f"UDP bind failed: {exc}")
            udp.close()
            return []

        print(f"TX UDP discovery -> {DISCOVERY_BROADCAST_IP}:{DOIP_UDP_PORT}")
        print(f"TX DoIP: {hex_bytes(msg)}")
        udp.sendto(msg, (DISCOVERY_BROADCAST_IP, DOIP_UDP_PORT))

        vehicles = []
        start = time.time()

        while time.time() - start < DISCOVERY_TIMEOUT:
            try:
                data, addr = udp.recvfrom(4096)
            except socket.timeout:
                break

            print(f"RX UDP from {addr[0]}:{addr[1]}")
            print(f"RX DoIP: {hex_bytes(data)}")

            try:
                _, payload_type, payload_len = parse_doip_header(data[:8])
            except Exception as exc:
                print(f"Ignore invalid DoIP response: {exc}")
                continue

            payload = data[8:8 + payload_len]

            if payload_type != PT_VEHICLE_ANNOUNCEMENT:
                print(f"Ignore payload_type=0x{payload_type:04X}")
                continue

            info = self._parse_vehicle_announcement(payload)
            info["ip"] = addr[0]
            vehicles.append(info)

            print("Found DoIP entity:")
            print(f"  IP: {addr[0]}")
            print(f"  VIN: {info['vin']}")
            print(f"  Entity Logical Address: 0x{info['logical_address']:04X}")
            print(f"  EID: {hex_bytes(info['eid'])}")
            print(f"  GID: {hex_bytes(info['gid'])}")
            print(f"  Further Action: 0x{info['further_action']:02X}")
            print(f"  Sync Status: 0x{info['sync_status']:02X}")

            if self.discovered_entity_addr is None:
                self.discovered_entity_addr = info["logical_address"]

        udp.close()

        if not vehicles:
            print("No DoIP vehicle found.")
        elif self.vehicle_ip is None:
            self.vehicle_ip = vehicles[0]["ip"]
            print(f"Auto selected vehicle IP: {self.vehicle_ip}")

        return vehicles

    def _parse_vehicle_announcement(self, payload: bytes) -> dict:
        return {
            "vin": payload[0:17].decode("ascii", errors="replace").strip("\x00") if len(payload) >= 17 else "",
            "logical_address": struct.unpack(">H", payload[17:19])[0] if len(payload) >= 19 else 0,
            "eid": payload[19:25] if len(payload) >= 25 else b"",
            "gid": payload[25:31] if len(payload) >= 31 else b"",
            "further_action": payload[31] if len(payload) >= 32 else 0,
            "sync_status": payload[32] if len(payload) >= 33 else 0,
        }

    def connect(self):
        if not self.vehicle_ip:
            print("Vehicle IP is not set. Use discover or ip <addr> first.")
            return False

        self.close()

        print(f"Connect TCP -> {self.vehicle_ip}:{DOIP_TCP_PORT}")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TCP_CONNECT_TIMEOUT)

        try:
            if LOCAL_BIND_IP != "0.0.0.0" or LOCAL_TCP_SOURCE_PORT != 0:
                sock.bind((LOCAL_BIND_IP, LOCAL_TCP_SOURCE_PORT))
            sock.connect((self.vehicle_ip, DOIP_TCP_PORT))
            sock.settimeout(TCP_RECV_TIMEOUT)
        except OSError as exc:
            print(f"TCP connect failed: {exc}")
            sock.close()
            return False

        self.sock = sock
        self.routing_activated = False
        print("TCP connected.")

        if AUTO_ROUTING_ACTIVATION:
            return self.routing_activation()

        return True

    def close(self):
        self.stop_tester_present()

        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass

        self.sock = None
        self.routing_activated = False
        self.routing_entity_addr = None

    def routing_activation(self):
        if not self.sock:
            print("TCP is not connected.")
            return False

        payload = (
                u16(self.tester_addr)
                + bytes([ROUTING_ACTIVATION_TYPE])
                + b"\x00\x00\x00\x00"
                + ROUTING_ACTIVATION_OEM_DATA
        )
        msg = build_doip_message(PT_ROUTING_ACTIVATION_REQUEST, payload)

        print(
            f"TX RoutingActivation: tester=0x{self.tester_addr:04X}, "
            f"type=0x{ROUTING_ACTIVATION_TYPE:02X}"
        )
        self._send_raw(msg)

        try:
            payload_type, payload = self._recv_doip_message()
        except Exception as exc:
            print(f"RoutingActivation failed: {exc}")
            return False

        if payload_type != PT_ROUTING_ACTIVATION_RESPONSE:
            print(f"Unexpected DoIP payload type: 0x{payload_type:04X}")
            return False

        if len(payload) < 5:
            print(f"Invalid RoutingActivation response: {hex_bytes(payload)}")
            return False

        tester = struct.unpack(">H", payload[0:2])[0]
        entity = struct.unpack(">H", payload[2:4])[0]
        code = payload[4]

        print(
            f"RX RoutingActivation: tester=0x{tester:04X}, "
            f"entity=0x{entity:04X}, code=0x{code:02X}"
        )

        if code == 0x10:
            self.routing_activated = True
            self.routing_entity_addr = entity
            print("RoutingActivation OK.")
            if self.target_addr == entity:
                print(
                    "Note: current UDS target equals DoIP entity address. "
                    "If this node is a gateway, set `target` to the real ECU logical address."
                )
            return True

        print("RoutingActivation rejected.")
        return False

    def send_uds(self, uds: bytes, wait_response: bool = True):
        if not self.sock:
            if not AUTO_CONNECT_BEFORE_UDS or not self.connect():
                return None

        if not self.routing_activated:
            if not self.routing_activation():
                return None

        payload = u16(self.tester_addr) + u16(self.target_addr) + uds
        msg = build_doip_message(PT_DIAGNOSTIC_MESSAGE, payload)

        print(
            f"TX UDS(source=0x{self.tester_addr:04X}, "
            f"target=0x{self.target_addr:04X}): {hex_bytes(uds)}"
        )
        if self.routing_entity_addr is not None and self.target_addr != self.routing_entity_addr:
            print(
                f"Route via DoIP entity 0x{self.routing_entity_addr:04X} -> "
                f"UDS target 0x{self.target_addr:04X}"
            )
        self._send_raw(msg)

        if not wait_response:
            return None

        return self._wait_uds_response()

    def _wait_uds_response(self):
        start = time.time()
        pending_start = None

        while time.time() - start <= UDS_RESPONSE_TIMEOUT:
            try:
                payload_type, payload = self._recv_doip_message()
            except socket.timeout:
                continue
            except Exception as exc:
                print(f"RX failed: {exc}")
                return None

            if payload_type == PT_DIAGNOSTIC_MESSAGE_POSITIVE_ACK:
                print(f"RX DoIP Diagnostic ACK: {hex_bytes(payload)}")
                print(
                    "DoIP ACK only: diagnostic message was accepted for routing. "
                    "Still waiting for UDS response (0x8001)."
                )
                continue

            if payload_type == PT_DIAGNOSTIC_MESSAGE_NEGATIVE_ACK:
                print(f"RX DoIP Diagnostic NACK: {hex_bytes(payload)}")
                return None

            if payload_type == PT_ALIVE_CHECK_REQUEST:
                self._alive_check_response()
                continue

            if payload_type != PT_DIAGNOSTIC_MESSAGE:
                print(f"RX other DoIP type=0x{payload_type:04X}, payload={hex_bytes(payload)}")
                continue

            if len(payload) < 5:
                print(f"RX invalid diagnostic payload: {hex_bytes(payload)}")
                return None

            source = struct.unpack(">H", payload[0:2])[0]
            target = struct.unpack(">H", payload[2:4])[0]
            uds = payload[4:]

            print(
                f"RX UDS(source=0x{source:04X}, "
                f"target=0x{target:04X}): {hex_bytes(uds)}"
            )
            print_uds_info(uds)

            if len(uds) >= 3 and uds[0] == 0x7F and uds[2] == 0x78:
                if pending_start is None:
                    pending_start = time.time()

                if time.time() - pending_start > UDS_RESPONSE_PENDING_MAX_WAIT:
                    print("ResponsePending wait timeout.")
                    return uds

                print("RX NRC 0x78 ResponsePending, keep waiting...")
                continue

            return uds

        if self.routing_entity_addr is not None:
            print(
                f"UDS response timeout. No diagnostic response from target "
                f"0x{self.target_addr:04X} via DoIP entity 0x{self.routing_entity_addr:04X}."
            )
            if self.target_addr == self.routing_entity_addr:
                print(
                    "Hint: target equals DoIP entity address. If this node is a gateway, "
                    "change `target` to the real ECU logical address."
                )
        else:
            print(f"UDS response timeout. No diagnostic response from target 0x{self.target_addr:04X}.")
        return None

    def _alive_check_response(self):
        payload = u16(self.tester_addr)
        msg = build_doip_message(PT_ALIVE_CHECK_RESPONSE, payload)
        print("RX AliveCheckRequest")
        self._send_raw(msg)

    def _send_raw(self, data: bytes):
        if PRINT_DOIP_RAW:
            print(f"TX DoIP: {hex_bytes(data)}")
        self.sock.sendall(data)

    def _recv_exact(self, size: int) -> bytes:
        data = b""
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise ConnectionError("TCP closed")
            data += chunk
        return data

    def _recv_doip_message(self):
        header = self._recv_exact(8)
        _, payload_type, payload_length = parse_doip_header(header)
        payload = self._recv_exact(payload_length) if payload_length else b""

        if PRINT_DOIP_RAW:
            print(f"RX DoIP: {hex_bytes(header + payload)}")

        return payload_type, payload

    def start_tester_present(self):
        if self.tester_present_running:
            print("TesterPresent already running.")
            return

        self.tester_present_running = True
        self.tester_present_thread = threading.Thread(
            target=self._tester_present_loop,
            daemon=True,
        )
        self.tester_present_thread.start()
        print(f"TesterPresent started, interval={TESTER_PRESENT_INTERVAL}s.")

    def stop_tester_present(self):
        if not self.tester_present_running:
            return

        self.tester_present_running = False

        if self.tester_present_thread:
            self.tester_present_thread.join(timeout=1.0)

        self.tester_present_thread = None
        print("TesterPresent stopped.")

    def _tester_present_loop(self):
        while self.tester_present_running:
            try:
                self.send_uds(bytes.fromhex("3E 00"), wait_response=False)
            except Exception as exc:
                print(f"TesterPresent failed: {exc}")
            time.sleep(TESTER_PRESENT_INTERVAL)


def print_help():
    print("""
Commands:

  help
    Show help.

  discover
    Search DoIP vehicle by UDP broadcast.

  ip <addr>
    Set vehicle DoIP IP.
    Example: ip 192.168.0.10

  connect
    Connect TCP and run Routing Activation if AUTO_ROUTING_ACTIVATION is True.

  ra
    Run Routing Activation manually.

  close
    Close TCP connection.

  source <hex>
    Set tester logical address.
    Example: source 0x0E00

  target <hex>
    Set target ECU logical address.
    Example: target 0x1234

  status
    Show current status.

  session default
    Send 10 01.

  session extended
    Send 10 03.

  session programming
    Send 10 02.

  read <DID>
    Send ReadDataByIdentifier.
    Example: read F190

  dtc
    Send 19 02 FF.

  clear <group>
    Send ClearDiagnosticInformation.
    Example: clear FFFFFF

  reset hard
    Send 11 01.

  reset soft
    Send 11 03.

  tp start
    Start TesterPresent 3E 00.

  tp stop
    Stop TesterPresent.

  <hex bytes>
    Send raw UDS directly.
    Example: 22 F1 90
    Example: 1003
    Example: 19 02 FF

  quit / exit
    Exit.
""")


def main():
    client = DoIPClient()

    print("DoIP + UDS console")
    print("Type help for commands.")
    print("Raw UDS can be sent directly, for example: 22 F1 90")
    print("")

    known_commands = {
        "help", "?", "discover", "ip", "connect", "ra", "close",
        "source", "target", "status", "session", "read", "dtc",
        "clear", "reset", "tp", "quit", "exit",
    }

    while True:
        try:
            line = input("doip> ").strip()
        except EOFError:
            break
        except KeyboardInterrupt:
            print("")
            break

        if not line:
            continue

        parts = line.split()
        command = parts[0].lower()
        args = parts[1:]

        try:
            if command in ("quit", "exit"):
                break

            if command in ("help", "?"):
                print_help()

            elif command == "discover":
                client.discover()

            elif command == "ip":
                if len(args) != 1:
                    print("Usage: ip <addr>")
                    continue
                client.vehicle_ip = args[0]
                print(f"Vehicle IP set: {client.vehicle_ip}")

            elif command == "connect":
                client.connect()

            elif command == "ra":
                client.routing_activation()

            elif command == "close":
                client.close()
                print("Connection closed.")

            elif command == "source":
                if len(args) != 1:
                    print("Usage: source <hex>")
                    continue
                client.tester_addr = parse_int(args[0])
                client.routing_activated = False
                print(f"Tester address set: 0x{client.tester_addr:04X}")

            elif command == "target":
                if len(args) != 1:
                    print("Usage: target <hex>")
                    continue
                client.target_addr = parse_int(args[0])
                print(f"Target address set: 0x{client.target_addr:04X}")

            elif command == "status":
                print(f"Vehicle IP: {client.vehicle_ip}")
                print(f"TCP connected: {client.sock is not None}")
                print(f"Routing activated: {client.routing_activated}")
                print(f"Tester logical address: 0x{client.tester_addr:04X}")
                print(f"Target logical address: 0x{client.target_addr:04X}")
                discovered = (
                    f"0x{client.discovered_entity_addr:04X}"
                    if client.discovered_entity_addr is not None else "unknown"
                )
                routing_entity = (
                    f"0x{client.routing_entity_addr:04X}"
                    if client.routing_entity_addr is not None else "unknown"
                )
                print(f"Discovered DoIP entity address: {discovered}")
                print(f"Routing Activation entity address: {routing_entity}")
                print(f"DoIP version: 0x{DOIP_PROTOCOL_VERSION:02X}")
                print(f"Routing activation type: 0x{ROUTING_ACTIVATION_TYPE:02X}")

            elif command == "session":
                if len(args) != 1:
                    print("Usage: session default|extended|programming")
                    continue

                session = args[0].lower()
                if session == "default":
                    client.send_uds(bytes.fromhex("10 01"))
                elif session == "extended":
                    client.send_uds(bytes.fromhex("10 03"))
                elif session == "programming":
                    client.send_uds(bytes.fromhex("10 02"))
                else:
                    print("Unknown session.")

            elif command == "read":
                if len(args) != 1:
                    print("Usage: read <DID>")
                    continue
                did = parse_int(args[0])
                client.send_uds(bytes([0x22]) + u16(did))

            elif command == "dtc":
                client.send_uds(bytes.fromhex("19 02 FF"))

            elif command == "clear":
                if len(args) != 1:
                    print("Usage: clear <DTC group>")
                    continue
                group = parse_int(args[0])
                client.send_uds(bytes([0x14]) + group.to_bytes(3, "big"))

            elif command == "reset":
                if len(args) != 1:
                    print("Usage: reset hard|soft")
                    continue

                if args[0].lower() == "hard":
                    client.send_uds(bytes.fromhex("11 01"))
                elif args[0].lower() == "soft":
                    client.send_uds(bytes.fromhex("11 03"))
                else:
                    print("Unknown reset type.")

            elif command == "tp":
                if len(args) != 1:
                    print("Usage: tp start|stop")
                    continue

                if args[0].lower() == "start":
                    client.start_tester_present()
                elif args[0].lower() == "stop":
                    client.stop_tester_present()
                else:
                    print("Usage: tp start|stop")

            elif command not in known_commands:
                uds = parse_hex_string(line)
                client.send_uds(uds)

            else:
                print(f"Unknown command: {command}")

        except ValueError as exc:
            print(f"Value error: {exc}")
        except OSError as exc:
            print(f"Network error: {exc}")
        except Exception as exc:
            print(f"Error: {exc}")

    client.close()
    print("Bye.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
