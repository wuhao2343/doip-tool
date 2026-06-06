"""
DoIP客户端模块 - 实现ISO 13400 DoIP协议通信层
支持车辆发现、路由激活、诊断消息收发等功能
"""

import logging
import socket
import struct
import threading
import time
from enum import IntEnum
from typing import Optional, Tuple, List, Dict

logger = logging.getLogger(__name__)


class DoIPPayloadType(IntEnum):
    """DoIP载荷类型定义 (ISO 13400-2)"""
    # 通用报头否定确认
    GENERIC_NACK = 0x0000
    # 车辆识别请求/响应
    VEHICLE_IDENTIFICATION_REQ = 0x0001
    VEHICLE_IDENTIFICATION_REQ_EID = 0x0002
    VEHICLE_IDENTIFICATION_REQ_VIN = 0x0003
    VEHICLE_ANNOUNCEMENT = 0x0004
    # 路由激活
    ROUTING_ACTIVATION_REQ = 0x0005
    ROUTING_ACTIVATION_RES = 0x0006
    # 存活检查
    ALIVE_CHECK_REQ = 0x0007
    ALIVE_CHECK_RES = 0x0008
    # DoIP实体状态
    DOIP_ENTITY_STATUS_REQ = 0x4001
    DOIP_ENTITY_STATUS_RES = 0x4002
    # 诊断电源模式
    DIAGNOSTIC_POWER_MODE_REQ = 0x4003
    DIAGNOSTIC_POWER_MODE_RES = 0x4004
    # 诊断消息
    DIAGNOSTIC_MESSAGE = 0x8001
    DIAGNOSTIC_MESSAGE_ACK = 0x8002
    DIAGNOSTIC_MESSAGE_NACK = 0x8003


class RoutingActivationType(IntEnum):
    """路由激活类型"""
    DEFAULT = 0x00
    WWH_OBD = 0x01
    CENTRAL_SECURITY = 0xE0


class DoIPNackCode(IntEnum):
    """通用否定确认代码"""
    INCORRECT_PATTERN = 0x00
    UNKNOWN_PAYLOAD_TYPE = 0x01
    MESSAGE_TOO_LARGE = 0x02
    OUT_OF_MEMORY = 0x03
    INVALID_PAYLOAD_LENGTH = 0x04


class RoutingActivationResponseCode(IntEnum):
    """路由激活响应代码"""
    UNKNOWN_SOURCE = 0x00
    NO_SOCKET = 0x01
    DIFFERENT_SOURCE = 0x02
    ALREADY_ACTIVE = 0x03
    MISSING_AUTHENTICATION = 0x04
    REJECTED_CONFIRMATION = 0x05
    UNSUPPORTED_ACTIVATION_TYPE = 0x06
    SUCCESS = 0x10
    CONFIRMATION_REQUIRED = 0x11


class DiagnosticNackCode(IntEnum):
    """诊断消息否定确认代码"""
    INVALID_SOURCE_ADDRESS = 0x02
    UNKNOWN_TARGET_ADDRESS = 0x03
    DIAGNOSTIC_MESSAGE_TOO_LARGE = 0x04
    OUT_OF_MEMORY = 0x05
    TARGET_UNREACHABLE = 0x06
    UNKNOWN_NETWORK = 0x07
    TRANSPORT_PROTOCOL_ERROR = 0x08


# DoIP协议常量
DOIP_PROTOCOL_VERSION = 0x02
DOIP_INVERSE_VERSION = 0xFD
DOIP_HEADER_LENGTH = 8
DOIP_UDP_DISCOVERY_PORT = 13400
DOIP_TCP_DATA_PORT = 13400
DOIP_UDP_BROADCAST = "255.255.255.255"


class DoIPMessage:
    """DoIP消息封装"""

    def __init__(self, payload_type: int, payload: bytes = b""):
        self.protocol_version = DOIP_PROTOCOL_VERSION
        self.inverse_version = DOIP_INVERSE_VERSION
        self.payload_type = payload_type
        self.payload = payload

    def serialize(self) -> bytes:
        """序列化为字节流"""
        header = struct.pack(
            ">BBHI",
            self.protocol_version,
            self.inverse_version,
            self.payload_type,
            len(self.payload)
        )
        return header + self.payload

    @staticmethod
    def deserialize(data: bytes) -> Optional['DoIPMessage']:
        """从字节流反序列化"""
        if len(data) < DOIP_HEADER_LENGTH:
            return None
        version, inverse, payload_type, payload_length = struct.unpack(
            ">BBHI", data[:DOIP_HEADER_LENGTH]
        )
        if len(data) < DOIP_HEADER_LENGTH + payload_length:
            return None
        msg = DoIPMessage(payload_type)
        msg.protocol_version = version
        msg.inverse_version = inverse
        msg.payload = data[DOIP_HEADER_LENGTH:DOIP_HEADER_LENGTH + payload_length]
        return msg

    def __repr__(self):
        try:
            type_name = DoIPPayloadType(self.payload_type).name
        except ValueError:
            type_name = f"0x{self.payload_type:04X}"
        return (f"DoIPMessage(type={type_name}, "
                f"payload_len={len(self.payload)}, "
                f"payload={self.payload.hex()})")


class VehicleInfo:
    """车辆识别信息"""

    def __init__(self, data: bytes, addr: Tuple[str, int]):
        self.ip = addr[0]
        self.port = addr[1]
        self.vin = ""
        self.logical_address = 0
        self.eid = b""
        self.gid = b""
        self.further_action = 0
        self.sync_status = 0
        self._parse(data)

    def _parse(self, data: bytes):
        """解析车辆公告/识别响应"""
        if len(data) >= 32:
            self.vin = data[0:17].decode("ascii", errors="replace").rstrip('\x00')
            self.logical_address = struct.unpack(">H", data[17:19])[0]
            self.eid = data[19:25]
            self.gid = data[25:31]
            self.further_action = data[31]
        if len(data) >= 33:
            self.sync_status = data[32]

    def __repr__(self):
        return (f"车辆信息:\n"
                f"  IP地址: {self.ip}:{self.port}\n"
                f"  VIN: {self.vin}\n"
                f"  逻辑地址: 0x{self.logical_address:04X}\n"
                f"  EID: {self.eid.hex()}\n"
                f"  GID: {self.gid.hex()}\n"
                f"  后续动作: 0x{self.further_action:02X}\n"
                f"  同步状态: 0x{self.sync_status:02X}")


class DoIPClient:
    """DoIP客户端 - 管理与DoIP网关的TCP/UDP通信"""

    def __init__(self, target_ip: str = "", target_port: int = DOIP_TCP_DATA_PORT,
                 source_address: int = 0x0E80, target_address: int = 0x0001,
                 timeout: float = 5.0, interface: str = ""):
        self.target_ip = target_ip
        self.target_port = target_port
        self.source_address = source_address
        self.target_address = target_address
        self.timeout = timeout
        self.interface = interface  # 绑定的网络接口IP

        self._tcp_socket: Optional[socket.socket] = None
        self._udp_socket: Optional[socket.socket] = None
        self._connected = False
        self._routing_activated = False
        self._lock = threading.Lock()
        self._recv_buffer = b""

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def is_routing_activated(self) -> bool:
        return self._routing_activated

    def discover_vehicles(self, timeout: float = 3.0,
                          broadcast_ip: str = "") -> List[VehicleInfo]:
        """UDP广播发现车辆"""
        vehicles = []
        broadcast = broadcast_ip or DOIP_UDP_BROADCAST

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(timeout)

            if self.interface:
                sock.bind((self.interface, 0))

            # 发送车辆识别请求
            msg = DoIPMessage(DoIPPayloadType.VEHICLE_IDENTIFICATION_REQ)
            sock.sendto(msg.serialize(), (broadcast, DOIP_UDP_DISCOVERY_PORT))
            logger.info(f"已发送车辆发现广播到 {broadcast}:{DOIP_UDP_DISCOVERY_PORT}")

            start_time = time.time()
            while time.time() - start_time < timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    resp = DoIPMessage.deserialize(data)
                    if resp and resp.payload_type == DoIPPayloadType.VEHICLE_ANNOUNCEMENT:
                        vehicle = VehicleInfo(resp.payload, addr)
                        vehicles.append(vehicle)
                        logger.info(f"发现车辆: {vehicle.ip} - {vehicle.vin}")
                except socket.timeout:
                    break
        except Exception as e:
            logger.error(f"车辆发现失败: {e}")
        finally:
            sock.close()

        return vehicles

    def connect(self) -> bool:
        """建立TCP连接"""
        if self._connected:
            logger.warning("已存在连接，请先断开")
            return True

        try:
            self._tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._tcp_socket.settimeout(self.timeout)

            if self.interface:
                self._tcp_socket.bind((self.interface, 0))

            self._tcp_socket.connect((self.target_ip, self.target_port))
            self._connected = True
            self._recv_buffer = b""
            logger.info(f"TCP连接成功: {self.target_ip}:{self.target_port}")
            return True
        except Exception as e:
            logger.error(f"TCP连接失败: {e}")
            self._connected = False
            return False

    def disconnect(self):
        """断开TCP连接"""
        self._routing_activated = False
        self._connected = False
        if self._tcp_socket:
            try:
                self._tcp_socket.close()
            except Exception:
                pass
            self._tcp_socket = None
        logger.info("TCP连接已断开")

    def activate_routing(self, activation_type: int = RoutingActivationType.DEFAULT,
                         oem_specific: bytes = b"") -> Tuple[bool, str]:
        """发送路由激活请求"""
        if not self._connected:
            return False, "未建立TCP连接"

        # 构建路由激活请求载荷
        payload = struct.pack(">HBxxxx", self.source_address, activation_type)
        if oem_specific:
            payload += oem_specific

        msg = DoIPMessage(DoIPPayloadType.ROUTING_ACTIVATION_REQ, payload)
        self._send_raw(msg.serialize())

        # 接收响应
        resp = self._receive_message(timeout=self.timeout)
        if not resp:
            return False, "路由激活响应超时"

        if resp.payload_type == DoIPPayloadType.ROUTING_ACTIVATION_RES:
            if len(resp.payload) >= 9:
                tester_addr = struct.unpack(">H", resp.payload[0:2])[0]
                entity_addr = struct.unpack(">H", resp.payload[2:4])[0]
                response_code = resp.payload[4]

                try:
                    code_name = RoutingActivationResponseCode(response_code).name
                except ValueError:
                    code_name = f"未知(0x{response_code:02X})"

                if response_code == RoutingActivationResponseCode.SUCCESS:
                    self._routing_activated = True
                    self.target_address = entity_addr
                    return True, f"路由激活成功 (实体地址: 0x{entity_addr:04X})"
                else:
                    return False, f"路由激活失败: {code_name}"
            return False, "路由激活响应格式错误"
        elif resp.payload_type == DoIPPayloadType.GENERIC_NACK:
            nack_code = resp.payload[0] if resp.payload else 0xFF
            return False, f"收到否定确认: 0x{nack_code:02X}"
        else:
            return False, f"收到意外响应类型: 0x{resp.payload_type:04X}"

    def send_diagnostic(self, data: bytes,
                        target_address: Optional[int] = None) -> Optional[bytes]:
        """发送诊断消息并等待响应"""
        if not self._routing_activated:
            logger.error("路由未激活，无法发送诊断消息")
            return None

        ta = target_address if target_address is not None else self.target_address

        # 构建诊断消息
        payload = struct.pack(">HH", self.source_address, ta) + data
        msg = DoIPMessage(DoIPPayloadType.DIAGNOSTIC_MESSAGE, payload)
        self._send_raw(msg.serialize())

        # 等待诊断消息确认
        ack = self._receive_message(timeout=self.timeout)
        if not ack:
            logger.error("诊断消息确认超时")
            return None

        if ack.payload_type == DoIPPayloadType.DIAGNOSTIC_MESSAGE_NACK:
            nack_code = ack.payload[4] if len(ack.payload) > 4 else 0xFF
            try:
                code_name = DiagnosticNackCode(nack_code).name
            except ValueError:
                code_name = f"0x{nack_code:02X}"
            logger.error(f"诊断消息被拒绝: {code_name}")
            return None

        if ack.payload_type != DoIPPayloadType.DIAGNOSTIC_MESSAGE_ACK:
            # 可能直接是诊断响应
            if ack.payload_type == DoIPPayloadType.DIAGNOSTIC_MESSAGE:
                if len(ack.payload) > 4:
                    return ack.payload[4:]
            logger.error(f"收到意外响应: 0x{ack.payload_type:04X}")
            return None

        # 等待诊断响应
        resp = self._receive_message(timeout=self.timeout)
        if not resp:
            logger.error("诊断响应超时")
            return None

        if resp.payload_type == DoIPPayloadType.DIAGNOSTIC_MESSAGE:
            if len(resp.payload) > 4:
                return resp.payload[4:]  # 跳过源/目标地址
        return None

    def send_diagnostic_raw(self, data: bytes,
                            target_address: Optional[int] = None) -> Tuple[bool, str, Optional[bytes]]:
        """发送原始诊断数据，返回(成功标志, 状态信息, 响应数据)"""
        if not self._routing_activated:
            return False, "路由未激活", None

        ta = target_address if target_address is not None else self.target_address
        payload = struct.pack(">HH", self.source_address, ta) + data
        msg = DoIPMessage(DoIPPayloadType.DIAGNOSTIC_MESSAGE, payload)
        self._send_raw(msg.serialize())

        # 等待ACK
        ack = self._receive_message(timeout=self.timeout)
        if not ack:
            return False, "确认超时", None

        if ack.payload_type == DoIPPayloadType.DIAGNOSTIC_MESSAGE_NACK:
            nack_code = ack.payload[4] if len(ack.payload) > 4 else 0xFF
            return False, f"消息被拒绝(0x{nack_code:02X})", None

        if ack.payload_type == DoIPPayloadType.DIAGNOSTIC_MESSAGE:
            resp_data = ack.payload[4:] if len(ack.payload) > 4 else b""
            return True, "收到响应", resp_data

        if ack.payload_type != DoIPPayloadType.DIAGNOSTIC_MESSAGE_ACK:
            return False, f"意外响应(0x{ack.payload_type:04X})", None

        # 等待诊断响应（支持长时间等待pending响应）
        while True:
            resp = self._receive_message(timeout=self.timeout)
            if not resp:
                return False, "响应超时", None

            if resp.payload_type == DoIPPayloadType.DIAGNOSTIC_MESSAGE:
                resp_data = resp.payload[4:] if len(resp.payload) > 4 else b""
                # 检查是否为NRC 0x78 (请求正确接收-响应待定)
                if len(resp_data) >= 3 and resp_data[0] == 0x7F and resp_data[2] == 0x78:
                    logger.info("收到NRC 0x78 (响应待定)，继续等待...")
                    continue
                return True, "收到响应", resp_data

            return False, f"意外响应(0x{resp.payload_type:04X})", None

    def get_entity_status(self) -> Optional[Dict]:
        """获取DoIP实体状态"""
        if not self._connected:
            return None

        msg = DoIPMessage(DoIPPayloadType.DOIP_ENTITY_STATUS_REQ)
        self._send_raw(msg.serialize())

        resp = self._receive_message(timeout=self.timeout)
        if resp and resp.payload_type == DoIPPayloadType.DOIP_ENTITY_STATUS_RES:
            if len(resp.payload) >= 7:
                node_type = resp.payload[0]
                max_sockets = resp.payload[1]
                cur_sockets = resp.payload[2]
                max_data_size = struct.unpack(">I", resp.payload[3:7])[0]
                return {
                    "node_type": node_type,
                    "max_tcp_sockets": max_sockets,
                    "current_tcp_sockets": cur_sockets,
                    "max_data_size": max_data_size
                }
        return None

    def get_power_mode(self) -> Optional[int]:
        """获取诊断电源模式"""
        if not self._connected:
            return None

        msg = DoIPMessage(DoIPPayloadType.DIAGNOSTIC_POWER_MODE_REQ)
        self._send_raw(msg.serialize())

        resp = self._receive_message(timeout=self.timeout)
        if resp and resp.payload_type == DoIPPayloadType.DIAGNOSTIC_POWER_MODE_RES:
            if len(resp.payload) >= 1:
                return resp.payload[0]
        return None

    def _send_raw(self, data: bytes):
        """发送原始字节数据"""
        with self._lock:
            if self._tcp_socket:
                self._tcp_socket.sendall(data)
                logger.debug(f"发送: {data.hex()}")

    def _receive_message(self, timeout: float = 5.0) -> Optional[DoIPMessage]:
        """接收一条DoIP消息"""
        if not self._tcp_socket:
            return None

        self._tcp_socket.settimeout(timeout)
        start_time = time.time()

        while time.time() - start_time < timeout:
            # 尝试从缓冲区解析
            if len(self._recv_buffer) >= DOIP_HEADER_LENGTH:
                _, _, _, payload_length = struct.unpack(
                    ">BBHI", self._recv_buffer[:DOIP_HEADER_LENGTH]
                )
                total_length = DOIP_HEADER_LENGTH + payload_length
                if len(self._recv_buffer) >= total_length:
                    msg_data = self._recv_buffer[:total_length]
                    self._recv_buffer = self._recv_buffer[total_length:]
                    msg = DoIPMessage.deserialize(msg_data)
                    if msg:
                        logger.debug(f"接收: {msg}")
                    return msg

            # 继续接收数据
            try:
                remaining = timeout - (time.time() - start_time)
                if remaining <= 0:
                    break
                self._tcp_socket.settimeout(min(remaining, 1.0))
                chunk = self._tcp_socket.recv(4096)
                if not chunk:
                    self._connected = False
                    return None
                self._recv_buffer += chunk
            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"接收数据异常: {e}")
                return None

        return None
