#!/usr/bin/env python3
"""
DoIP ECU模拟器 - 在本地模拟一个DoIP网关+ECU
用于在没有实车的情况下测试DoIP诊断工具

用法: python doip_simulator.py [端口]
默认端口: 13400
"""

import logging
import socket
import struct
import sys
import threading

logging.basicConfig(level=logging.INFO, format="%(asctime)s [模拟器] %(message)s")
logger = logging.getLogger(__name__)

# DoIP常量
DOIP_HEADER_LEN = 8
PROTOCOL_VERSION = 0x02
INVERSE_VERSION = 0xFD

# 模拟DoIP网关和后端ECU地址
GATEWAY_LOGICAL_ADDRESS = 0x1720
ECU_LOGICAL_ADDRESS = 0x07E0

# RST模拟配置
# False: 正常行为
# True: 命中条件时在收到诊断请求后立即TCP RST断开
SIMULATE_TCP_RST_ON_DIAG = True

# 触发RST的目标地址。None 表示任意目标地址都触发。
RST_TRIGGER_TARGET = 0x1721

# 触发RST的UDS服务ID。None 表示任意服务都触发。
RST_TRIGGER_SID = None

# 模拟ECU数据
ECU_DATA = {
    # DID: 数据内容
    0xF190: b"LSVAB1234S0000001",  # VIN码
    0xF187: b"31234567890",  # 零件号
    0xF188: b"SW_V2.1.0",  # 软件版本号
    0xF189: b"2024-03-15",  # 软件版本日期
    0xF18A: b"SUPPLIER_001",  # 供应商标识
    0xF18B: b"20240101",  # 生产日期
    0xF18C: b"SN20240001",  # 序列号
    0xF191: b"HW_V1.0",  # 硬件版本号
    0xF192: b"SUP_HW_V1.0",  # 供应商硬件版本号
    0xF193: b"SUP_SW_V2.1",  # 供应商软件版本号
    0xF194: b"20240310",  # 供应商软件日期
    0xF197: b"GW_MODULE",  # 系统名称
    0xF198: b"TESTER_001",  # Tester序列号
    0xF199: b"20240315",  # 编程日期
    0xF186: b"\x01",  # 当前会话(默认)
}

# 模拟DTC列表 (DTC 3字节 + 状态1字节)
ECU_DTCS = [
    (0x062300, 0x29),  # 确认+当前故障
    (0x091187, 0x24),  # 待定
    (0x0C0100, 0x08),  # 已确认，非当前
]

# 模拟ECU状态
ecu_state = {
    "session": 0x01,  # 当前会话
    "security_level": 0,  # 安全等级 (0=未解锁)
    "dtc_setting": True,  # DTC记录开关
    "comm_control": True,  # 通信控制
}

# 安全访问种子（模拟用固定值）
SECURITY_SEED = b"\x12\x34\x56\x78"
SECURITY_KEY = b"\x87\x65\x43\x21"  # 期望的密钥（实际是种子取反）


def reset_ecu_state():
    ecu_state["session"] = 0x01
    ecu_state["security_level"] = 0
    ecu_state["dtc_setting"] = True
    ecu_state["comm_control"] = True
    ECU_DATA[0xF186] = b"\x01"


def build_doip_header(payload_type: int, payload_length: int) -> bytes:
    return struct.pack(">BBHI", PROTOCOL_VERSION, INVERSE_VERSION,
                       payload_type, payload_length)


def build_doip_message(payload_type: int, payload: bytes) -> bytes:
    return build_doip_header(payload_type, len(payload)) + payload


def should_simulate_tcp_rst(target_addr: int, uds_data: bytes) -> bool:
    if not SIMULATE_TCP_RST_ON_DIAG:
        return False

    if RST_TRIGGER_TARGET is not None and target_addr != RST_TRIGGER_TARGET:
        return False

    if RST_TRIGGER_SID is not None:
        if not uds_data or uds_data[0] != RST_TRIGGER_SID:
            return False

    return True


def abort_connection_with_rst(conn: socket.socket, reason: str):
    logger.info(f"模拟TCP RST断开: {reason}")
    try:
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("hh", 1, 0))
    except OSError as exc:
        logger.warning(f"设置SO_LINGER失败，将直接关闭连接: {exc}")
    conn.close()


def handle_diagnostic_message(source_addr: int, target_addr: int,
                              uds_data: bytes) -> bytes:
    """处理UDS诊断请求，返回UDS响应数据"""
    if len(uds_data) == 0:
        return b"\x7F\x00\x13"  # 消息长度错误

    sid = uds_data[0]

    # 0x10 诊断会话控制
    if sid == 0x10:
        if len(uds_data) < 2:
            return b"\x7F\x10\x13"
        session = uds_data[1]
        if session in (0x01, 0x02, 0x03):
            ecu_state["session"] = session
            ECU_DATA[0xF186] = bytes([session])
            # 肯定响应: SID+0x40, 子功能, P2时间, P2*时间
            return bytes([0x50, session, 0x00, 0x32, 0x01, 0xF4])
        else:
            return b"\x7F\x10\x12"  # 子功能不支持

    # 0x11 ECU复位
    elif sid == 0x11:
        if len(uds_data) < 2:
            return b"\x7F\x11\x13"
        reset_type = uds_data[1]
        if reset_type in (0x01, 0x02, 0x03):
            ecu_state["session"] = 0x01
            return bytes([0x51, reset_type])
        else:
            return b"\x7F\x11\x12"

    # 0x22 读取DID
    elif sid == 0x22:
        if len(uds_data) < 3:
            return b"\x7F\x22\x13"
        response = bytes([0x62])
        i = 1
        while i + 1 < len(uds_data):
            did = struct.unpack(">H", uds_data[i:i + 2])[0]
            if did in ECU_DATA:
                response += struct.pack(">H", did) + ECU_DATA[did]
            else:
                return bytes([0x7F, 0x22, 0x31])  # 请求超出范围
            i += 2
        return response

    # 0x2E 写入DID
    elif sid == 0x2E:
        if len(uds_data) < 4:
            return b"\x7F\x2E\x13"
        if ecu_state["session"] == 0x01:
            return b"\x7F\x2E\x7F"  # 当前会话不支持
        if ecu_state["security_level"] == 0:
            return b"\x7F\x2E\x33"  # 安全访问拒绝
        did = struct.unpack(">H", uds_data[1:3])[0]
        data = uds_data[3:]
        ECU_DATA[did] = data
        return bytes([0x6E]) + struct.pack(">H", did)

    # 0x27 安全访问
    elif sid == 0x27:
        if len(uds_data) < 2:
            return b"\x7F\x27\x13"
        sub = uds_data[1]
        if ecu_state["session"] == 0x01:
            return b"\x7F\x27\x7F"  # 默认会话不支持
        if sub % 2 == 1:  # 奇数=请求种子
            if ecu_state["security_level"] >= sub:
                return bytes([0x67, sub, 0x00, 0x00, 0x00, 0x00])  # 已解锁
            return bytes([0x67, sub]) + SECURITY_SEED
        else:  # 偶数=发送密钥
            key = uds_data[2:]
            if key == SECURITY_KEY:
                ecu_state["security_level"] = sub - 1
                return bytes([0x67, sub])
            else:
                return b"\x7F\x27\x35"  # 无效密钥

    # 0x3E TesterPresent
    elif sid == 0x3E:
        sub = uds_data[1] if len(uds_data) > 1 else 0x00
        if sub == 0x80:
            return None  # 抑制响应
        return bytes([0x7E, 0x00])

    # 0x14 清除DTC
    elif sid == 0x14:
        if len(uds_data) < 4:
            return b"\x7F\x14\x13"
        ECU_DTCS.clear()
        return bytes([0x54])

    # 0x19 读取DTC信息
    elif sid == 0x19:
        if len(uds_data) < 2:
            return b"\x7F\x19\x13"
        sub = uds_data[1]

        if sub == 0x01:  # 按状态掩码读DTC数量
            mask = uds_data[2] if len(uds_data) > 2 else 0xFF
            count = sum(1 for _, s in ECU_DTCS if s & mask)
            return bytes([0x59, 0x01, mask]) + struct.pack(">H", count)

        elif sub == 0x02:  # 按状态掩码报告DTC
            mask = uds_data[2] if len(uds_data) > 2 else 0xFF
            response = bytes([0x59, 0x02, mask])
            for dtc, status in ECU_DTCS:
                if status & mask:
                    response += struct.pack(">I", dtc)[1:] + bytes([status])
            return response

        elif sub == 0x0A:  # 支持的DTC
            response = bytes([0x59, 0x0A])
            for dtc, status in ECU_DTCS:
                response += struct.pack(">I", dtc)[1:] + bytes([status])
            return response

        else:
            return b"\x7F\x19\x12"

    # 0x28 通信控制
    elif sid == 0x28:
        if len(uds_data) < 3:
            return b"\x7F\x28\x13"
        if ecu_state["session"] == 0x01:
            return b"\x7F\x28\x7F"
        control_type = uds_data[1]
        ecu_state["comm_control"] = (control_type == 0x00)
        return bytes([0x68, control_type])

    # 0x85 DTC设置控制
    elif sid == 0x85:
        if len(uds_data) < 2:
            return b"\x7F\x85\x13"
        if ecu_state["session"] == 0x01:
            return b"\x7F\x85\x7F"
        setting_type = uds_data[1]
        ecu_state["dtc_setting"] = (setting_type == 0x01)
        return bytes([0xC5, setting_type])

    # 0x31 例程控制
    elif sid == 0x31:
        if len(uds_data) < 4:
            return b"\x7F\x31\x13"
        if ecu_state["session"] == 0x01:
            return b"\x7F\x31\x7F"
        control_type = uds_data[1]
        routine_id = struct.unpack(">H", uds_data[2:4])[0]
        return bytes([0x71, control_type]) + struct.pack(">H", routine_id) + b"\x00"

    # 0x2F IO控制
    elif sid == 0x2F:
        if len(uds_data) < 4:
            return b"\x7F\x2F\x13"
        if ecu_state["session"] == 0x01:
            return b"\x7F\x2F\x7F"
        did = struct.unpack(">H", uds_data[1:3])[0]
        control_param = uds_data[3]
        return bytes([0x6F]) + struct.pack(">H", did) + bytes([control_param, 0x00])

    # 0x23 按地址读内存
    elif sid == 0x23:
        if ecu_state["security_level"] == 0:
            return b"\x7F\x23\x33"
        # 返回模拟数据
        return bytes([0x63]) + b"\xAA\xBB\xCC\xDD" * 4

    # 0x34 请求下载
    elif sid == 0x34:
        if ecu_state["session"] != 0x02:
            return b"\x7F\x34\x7F"
        if ecu_state["security_level"] == 0:
            return b"\x7F\x34\x33"
        # 返回最大块长度 4096
        return bytes([0x74, 0x20, 0x10, 0x00])

    # 0x36 传输数据
    elif sid == 0x36:
        if len(uds_data) < 2:
            return b"\x7F\x36\x13"
        block_counter = uds_data[1]
        return bytes([0x76, block_counter])

    # 0x37 请求传输退出
    elif sid == 0x37:
        return bytes([0x77])

    # 未知服务
    else:
        return bytes([0x7F, sid, 0x11])  # 服务不支持


def handle_client(conn: socket.socket, addr):
    """处理单个TCP客户端连接"""
    logger.info(f"客户端连接: {addr}")
    routing_activated = False
    tester_addr = 0
    entity_addr = GATEWAY_LOGICAL_ADDRESS

    buffer = b""

    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break

            buffer += data

            while len(buffer) >= DOIP_HEADER_LEN:
                version, inverse, payload_type, payload_len = struct.unpack(
                    ">BBHI", buffer[:DOIP_HEADER_LEN]
                )

                if len(buffer) < DOIP_HEADER_LEN + payload_len:
                    break  # 数据不完整，等待更多数据

                payload = buffer[DOIP_HEADER_LEN:DOIP_HEADER_LEN + payload_len]
                buffer = buffer[DOIP_HEADER_LEN + payload_len:]

                # 路由激活请求
                if payload_type == 0x0005:
                    if len(payload) >= 3:
                        tester_addr = struct.unpack(">H", payload[0:2])[0]
                        activation_type = payload[2]
                        routing_activated = True
                        # 路由激活响应
                        resp_payload = struct.pack(">HHBxxxx",
                                                   tester_addr, entity_addr, 0x10)
                        resp = build_doip_message(0x0006, resp_payload)
                        conn.sendall(resp)
                        logger.info(
                            f"路由激活成功 - 测试仪: 0x{tester_addr:04X}, "
                            f"网关实体: 0x{entity_addr:04X}, 类型: 0x{activation_type:02X}"
                        )

                # DoIP实体状态请求
                elif payload_type == 0x4001:
                    # 节点类型=网关, 最大连接=5, 当前=1, 最大数据=4096
                    resp_payload = bytes([0x00, 0x05, 0x01]) + struct.pack(">I", 4096)
                    resp = build_doip_message(0x4002, resp_payload)
                    conn.sendall(resp)

                # 诊断电源模式请求
                elif payload_type == 0x4003:
                    resp = build_doip_message(0x4004, bytes([0x01]))  # 就绪
                    conn.sendall(resp)

                # 存活检查请求
                elif payload_type == 0x0007:
                    resp_payload = struct.pack(">H", tester_addr)
                    resp = build_doip_message(0x0008, resp_payload)
                    conn.sendall(resp)

                # 诊断消息
                elif payload_type == 0x8001:
                    if not routing_activated:
                        nack = struct.pack(">HHB", tester_addr, entity_addr, 0x02)
                        resp = build_doip_message(0x8003, nack)
                        conn.sendall(resp)
                        continue

                    if len(payload) >= 4:
                        src = struct.unpack(">H", payload[0:2])[0]
                        dst = struct.unpack(">H", payload[2:4])[0]
                        uds_data = payload[4:]

                        logger.info(
                            f"网关收到诊断请求 [{src:04X}->{dst:04X}]: "
                            f"{uds_data.hex().upper()}"
                        )

                        if should_simulate_tcp_rst(dst, uds_data):
                            abort_connection_with_rst(
                                conn,
                                f"target=0x{dst:04X}, uds={uds_data.hex().upper()}"
                            )
                            return

                        # 发送ACK
                        ack_payload = struct.pack(">HHB", dst, src, 0x00)
                        ack = build_doip_message(0x8002, ack_payload)
                        conn.sendall(ack)
                        logger.info(
                            f"网关已发送DoIP ACK [{dst:04X}->{src:04X}], ack_code=0x00"
                        )

                        if dst == ECU_LOGICAL_ADDRESS:
                            logger.info(
                                f"网关路由到后端ECU 0x{ECU_LOGICAL_ADDRESS:04X}"
                            )
                            uds_response = handle_diagnostic_message(src, dst, uds_data)
                            if uds_response:
                                diag_payload = struct.pack(">HH", dst, src) + uds_response
                                diag_resp = build_doip_message(0x8001, diag_payload)
                                conn.sendall(diag_resp)
                                logger.info(
                                    f"后端ECU响应 [{dst:04X}->{src:04X}]: "
                                    f"{uds_response.hex().upper()}"
                                )
                            else:
                                logger.info(
                                    f"后端ECU 0x{ECU_LOGICAL_ADDRESS:04X} 抑制响应"
                                )

                        elif dst == GATEWAY_LOGICAL_ADDRESS:
                            logger.info(
                                f"请求目标是DoIP网关实体 0x{GATEWAY_LOGICAL_ADDRESS:04X}。"
                                "模拟器仅返回DoIP ACK，不返回UDS响应，"
                                "用于模拟把网关地址误当成ECU地址的场景。"
                            )

                        else:
                            logger.info(
                                f"网关没有到目标 0x{dst:04X} 的路由。"
                                "模拟器仅返回DoIP ACK，不返回UDS响应。"
                            )

                else:
                    logger.warning(f"未知载荷类型: 0x{payload_type:04X}")
                    nack = bytes([0x01])  # 未知载荷类型
                    resp = build_doip_message(0x0000, nack)
                    conn.sendall(resp)

    except (ConnectionResetError, ConnectionAbortedError):
        pass
    except Exception as e:
        logger.error(f"处理客户端异常: {e}")
    finally:
        conn.close()
        logger.info(f"客户端断开: {addr}")
        reset_ecu_state()


def run_udp_server(port: int):
    """UDP服务器 - 处理车辆发现广播"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    logger.info(f"UDP发现服务已启动 (端口: {port})")

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            if len(data) >= DOIP_HEADER_LEN:
                _, _, payload_type, _ = struct.unpack(">BBHI", data[:DOIP_HEADER_LEN])

                # 车辆识别请求
                if payload_type in (0x0001, 0x0002, 0x0003):
                    logger.info(f"收到车辆发现请求 from {addr}")
                    # 构建车辆公告响应
                    vin = b"LSVAB1234S0000001"  # 17字节VIN
                    logical_addr = struct.pack(">H", GATEWAY_LOGICAL_ADDRESS)
                    eid = b"\x00\x11\x22\x33\x44\x55"  # 6字节EID
                    gid = b"\xAA\xBB\xCC\xDD\xEE\xFF"  # 6字节GID
                    further_action = b"\x00"
                    sync_status = b"\x00"

                    announcement = (vin + logical_addr + eid + gid +
                                     further_action + sync_status)
                    resp = build_doip_message(0x0004, announcement)
                    sock.sendto(resp, addr)
                    logger.info(
                        f"已发送车辆公告到 {addr}, 网关实体地址: 0x{GATEWAY_LOGICAL_ADDRESS:04X}"
                    )

        except Exception as e:
            logger.error(f"UDP处理异常: {e}")


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 13400

    print("=" * 60)
    print("  DoIP 网关 + ECU 模拟器")
    print("=" * 60)
    print(f"  TCP诊断端口:  {port}")
    print(f"  UDP发现端口:  {port}")
    print(f"  DoIP网关地址: 0x{GATEWAY_LOGICAL_ADDRESS:04X}")
    print(f"  后端ECU地址:  0x{ECU_LOGICAL_ADDRESS:04X}")
    print(f"  模拟VIN:      LSVAB1234S0000001")
    print(f"  安全访问密钥: {SECURITY_KEY.hex().upper()}")
    print(f"  TCP RST模拟:  {'ON' if SIMULATE_TCP_RST_ON_DIAG else 'OFF'}")
    print("=" * 60)
    print("  模拟功能:")
    print("    - 车辆发现 (UDP广播响应)")
    print("    - 路由激活 (返回网关地址 0x1720)")
    print("    - 网关转发到后端ECU 0x07E0")
    print("    - 误发到网关地址时仅回DoIP ACK，不回UDS")
    print("    - 可选: 收到诊断请求后立即TCP RST断开")
    print("    - 会话控制 (01/02/03)")
    print("    - 安全访问 (种子/密钥)")
    print("    - DID读写 (含VIN/软件版本等)")
    print("    - DTC读取/清除")
    print("    - 通信控制")
    print("    - DTC设置控制")
    print("    - 例程控制")
    print("    - IO控制")
    print("    - 固件下载模拟")
    print("    - ECU复位")
    print("    - TesterPresent")
    print("=" * 60)
    print("  示例:")
    print("    正确目标: ip 127.0.0.1 -> target 0x07E0 -> connect -> 10 01 -> 22 F1 90")
    print("    错误目标: ip 127.0.0.1 -> target 0x1720 -> connect -> 22 F1 90")
    if SIMULATE_TCP_RST_ON_DIAG:
        trigger_target = "ANY" if RST_TRIGGER_TARGET is None else f"0x{RST_TRIGGER_TARGET:04X}"
        trigger_sid = "ANY" if RST_TRIGGER_SID is None else f"0x{RST_TRIGGER_SID:02X}"
        print(f"    RST触发条件: target={trigger_target}, sid={trigger_sid}")
    print("=" * 60)

    # 启动UDP服务
    udp_thread = threading.Thread(target=run_udp_server, args=(port,), daemon=True)
    udp_thread.start()

    # 启动TCP服务
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(5)
    logger.info(f"TCP诊断服务已启动 (端口: {port})")

    try:
        while True:
            conn, addr = server.accept()
            client_thread = threading.Thread(target=handle_client,
                                             args=(conn, addr), daemon=True)
            client_thread.start()
    except KeyboardInterrupt:
        print("\n  模拟器已停止")
    finally:
        server.close()


if __name__ == "__main__":
    main()
