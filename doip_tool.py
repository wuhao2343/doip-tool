import cmd
import logging
import os
import struct
import sys
import threading
import time
from typing import Optional

from doip_client import (
    DoIPClient, RoutingActivationType,
    DOIP_TCP_DATA_PORT
)
from uds_service import (
    UDSClient, COMMON_DIDS, UDSResponse
)

# 配置日志
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
logging.basicConfig(level=logging.WARNING, format=LOG_FORMAT)
logger = logging.getLogger(__name__)

BANNER = r"""
=============================================================
    ____        _____ ____    ______            __
   / __ \____  /  _/ __ \  /_  __/___  ____  / /
  / / / / __ \ / // /_/ /   / / / __ \/ __ \/ /
 / /_/ / /_/ // // ____/   / / / /_/ / /_/ / /
/_____/\____/___/_/       /_/  \____/\____/_/

  DoIP诊断工具 v1.0 - 车载以太网诊断测试
  协议: ISO 13400 (DoIP) + ISO 14229 (UDS)
=============================================================
输入 'help' 查看可用命令, 输入 'quit' 退出
"""


class TesterPresentThread:
    """TesterPresent保活线程"""

    def __init__(self, uds_client: UDSClient, interval: float = 2.0):
        self.uds_client = uds_client
        self.interval = interval
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None

    @property
    def is_running(self) -> bool:
        return self._running

    def _run(self):
        while self._running:
            try:
                self.uds_client.tester_present(suppress_response=True)
            except Exception:
                pass
            time.sleep(self.interval)


class DoIPTool(cmd.Cmd):
    """DoIP诊断工具命令行界面"""

    prompt = "\033[36mDoIP>\033[0m "
    intro = BANNER

    def __init__(self):
        super().__init__()
        self.doip_client: Optional[DoIPClient] = None
        self.uds_client: Optional[UDSClient] = None
        self.tp_thread: Optional[TesterPresentThread] = None

        # 默认参数
        self.target_ip = ""
        self.target_port = DOIP_TCP_DATA_PORT
        self.source_address = 0x0E80
        self.target_address = 0x0001
        self.timeout = 5.0
        self.interface = ""
        self.log_level = "WARNING"

    def emptyline(self):
        pass

    def default(self, line):
        print(f"  未知命令: '{line}', 输入 'help' 查看可用命令")

    # ==================== 连接管理 ====================

    def do_discover(self, arg):
        """发现网络中的DoIP车辆\n用法: discover [超时秒数] [广播地址]"""
        args = arg.split()
        timeout = float(args[0]) if args else 3.0
        broadcast = args[1] if len(args) > 1 else ""

        client = DoIPClient(interface=self.interface)
        print(f"  正在发送车辆发现广播 (超时: {timeout}s)...")
        vehicles = client.discover_vehicles(timeout=timeout, broadcast_ip=broadcast)

        if vehicles:
            print(f"\n  发现 {len(vehicles)} 个DoIP实体:")
            print("  " + "-" * 60)
            for i, v in enumerate(vehicles, 1):
                print(f"  [{i}] {v}")
                print("  " + "-" * 60)
        else:
            print("  未发现任何DoIP实体")

    def do_config(self, arg):
        """配置连接参数\n用法: config [参数名] [值]\n参数: ip, port, sa, ta, timeout, interface, log"""
        args = arg.split()
        if not args:
            print("  当前配置:")
            print(f"    目标IP:      {self.target_ip or '(未设置)'}")
            print(f"    目标端口:    {self.target_port}")
            print(f"    源地址(SA):  0x{self.source_address:04X}")
            print(f"    目标地址(TA):0x{self.target_address:04X}")
            print(f"    超时时间:    {self.timeout}s")
            print(f"    绑定接口:    {self.interface or '(自动)'}")
            print(f"    日志级别:    {self.log_level}")
            connected = self.doip_client.is_connected if self.doip_client else False
            activated = self.doip_client.is_routing_activated if self.doip_client else False
            tp_running = self.tp_thread.is_running if self.tp_thread else False
            print(f"    连接状态:    {'已连接' if connected else '未连接'}")
            print(f"    路由状态:    {'已激活' if activated else '未激活'}")
            print(f"    保活状态:    {'运行中' if tp_running else '已停止'}")
            return

        param = args[0].lower()
        if len(args) < 2:
            print(f"  请提供参数值, 用法: config {param} <值>")
            return

        value = args[1]
        if param == "ip":
            self.target_ip = value
            print(f"  目标IP已设置为: {value}")
        elif param == "port":
            self.target_port = int(value)
            print(f"  目标端口已设置为: {value}")
        elif param == "sa":
            self.source_address = int(value, 16) if value.startswith("0x") else int(value)
            print(f"  源地址已设置为: 0x{self.source_address:04X}")
        elif param == "ta":
            self.target_address = int(value, 16) if value.startswith("0x") else int(value)
            print(f"  目标地址已设置为: 0x{self.target_address:04X}")
        elif param == "timeout":
            self.timeout = float(value)
            print(f"  超时时间已设置为: {self.timeout}s")
        elif param == "interface":
            self.interface = value
            print(f"  绑定接口已设置为: {value}")
        elif param == "log":
            self.log_level = value.upper()
            logging.getLogger().setLevel(getattr(logging, self.log_level, logging.WARNING))
            print(f"  日志级别已设置为: {self.log_level}")
        else:
            print(f"  未知参数: {param}")
            print("  可用参数: ip, port, sa, ta, timeout, interface, log")

    def do_connect(self, arg):
        """连接到DoIP网关\n用法: connect [IP地址] [端口]"""
        args = arg.split()
        if args:
            self.target_ip = args[0]
        if len(args) > 1:
            self.target_port = int(args[1])

        if not self.target_ip:
            print("  错误: 请先设置目标IP (config ip <地址> 或 connect <IP>)")
            return

        # 断开已有连接
        if self.doip_client and self.doip_client.is_connected:
            self._stop_tp()
            self.doip_client.disconnect()

        self.doip_client = DoIPClient(
            target_ip=self.target_ip,
            target_port=self.target_port,
            source_address=self.source_address,
            target_address=self.target_address,
            timeout=self.timeout,
            interface=self.interface
        )

        print(f"  正在连接 {self.target_ip}:{self.target_port} ...")
        if self.doip_client.connect():
            self.uds_client = UDSClient(self.doip_client)
            print("  TCP连接成功!")
        else:
            print("  TCP连接失败!")

    def do_activate(self, arg):
        """激活路由\n用法: activate [激活类型: 0=默认, 1=WWH-OBD, E0=中央安全]"""
        if not self._check_connected():
            return

        activation_type = RoutingActivationType.DEFAULT
        if arg.strip():
            activation_type = int(arg.strip(), 16)

        print(f"  正在激活路由 (类型: 0x{activation_type:02X})...")
        success, msg = self.doip_client.activate_routing(activation_type)
        if success:
            print(f"  {msg}")
            self.target_address = self.doip_client.target_address
        else:
            print(f"  {msg}")

    def do_disconnect(self, arg):
        """断开连接"""
        self._stop_tp()
        if self.doip_client:
            self.doip_client.disconnect()
            print("  已断开连接")
        else:
            print("  当前无活动连接")

    def do_status(self, arg):
        """查询DoIP实体状态"""
        if not self._check_connected():
            return

        status = self.doip_client.get_entity_status()
        if status:
            node_types = {0: "DoIP网关", 1: "DoIP节点"}
            print("  DoIP实体状态:")
            print(f"    节点类型:     {node_types.get(status['node_type'], '未知')}")
            print(f"    最大TCP连接:  {status['max_tcp_sockets']}")
            print(f"    当前TCP连接:  {status['current_tcp_sockets']}")
            print(f"    最大数据长度: {status['max_data_size']} 字节")
        else:
            print("  获取实体状态失败")

    def do_powermode(self, arg):
        """查询诊断电源模式"""
        if not self._check_connected():
            return

        mode = self.doip_client.get_power_mode()
        if mode is not None:
            modes = {0: "未就绪", 1: "就绪", 2: "不支持"}
            print(f"  诊断电源模式: {modes.get(mode, f'未知(0x{mode:02X})')}")
        else:
            print("  获取电源模式失败")

    # ==================== 会话管理 ====================

    def do_session(self, arg):
        """切换诊断会话\n用法: session <类型>\n类型: 1=默认, 2=编程, 3=扩展, 或自定义值"""
        if not self._check_activated():
            return

        if not arg.strip():
            print("  用法: session <会话类型>")
            print("  类型: 1=默认会话, 2=编程会话, 3=扩展诊断会话")
            return

        session_type = int(arg.strip(), 16) if arg.strip().startswith("0x") else int(arg.strip())
        session_names = {1: "默认会话", 2: "编程会话", 3: "扩展诊断会话"}
        name = session_names.get(session_type, f"自定义会话(0x{session_type:02X})")

        print(f"  正在切换到{name}...")
        resp = self.uds_client.diagnostic_session_control(session_type)
        self._print_response(resp)

    def do_tp(self, arg):
        """TesterPresent保活控制\n用法: tp [start|stop|once] [间隔秒数]"""
        if not self._check_activated():
            return

        args = arg.split()
        action = args[0].lower() if args else "once"

        if action == "start":
            interval = float(args[1]) if len(args) > 1 else 2.0
            if self.tp_thread and self.tp_thread.is_running:
                print("  保活已在运行中")
                return
            self.tp_thread = TesterPresentThread(self.uds_client, interval)
            self.tp_thread.start()
            print(f"  TesterPresent保活已启动 (间隔: {interval}s)")
        elif action == "stop":
            self._stop_tp()
            print("  TesterPresent保活已停止")
        else:
            resp = self.uds_client.tester_present(suppress_response=False)
            self._print_response(resp)

    # ==================== ECU复位 ====================

    def do_reset(self, arg):
        """ECU复位\n用法: reset <类型>\n类型: 1=硬复位, 2=KL15复位, 3=软复位"""
        if not self._check_activated():
            return

        if not arg.strip():
            print("  用法: reset <复位类型>")
            print("  类型: 1=硬复位, 2=KL15复位, 3=软复位")
            return

        reset_type = int(arg.strip())
        reset_names = {1: "硬复位", 2: "KL15复位", 3: "软复位"}
        name = reset_names.get(reset_type, f"复位(0x{reset_type:02X})")

        print(f"  正在执行{name}...")
        resp = self.uds_client.ecu_reset(reset_type)
        self._print_response(resp)

    # ==================== 安全访问 ====================

    def do_security(self, arg):
        """安全访问\n用法: security <级别> [密钥hex]\n示例: security 1\n      security 1 0102030405"""
        if not self._check_activated():
            return

        args = arg.split()
        if not args:
            print("  用法: security <安全级别> [密钥hex]")
            print("  示例: security 1         (请求种子)")
            print("        security 1 AABB... (自动请求种子+发送密钥)")
            return

        level = int(args[0])

        # 请求种子
        print(f"  请求安全访问种子 (级别: 0x{level:02X})...")
        resp = self.uds_client.security_access_request_seed(level)
        self._print_response(resp)

        if resp.positive and len(args) > 1:
            # 发送密钥
            key = bytes.fromhex(args[1])
            print(f"  发送密钥: {key.hex()}")
            resp2 = self.uds_client.security_access_send_key(level, key)
            self._print_response(resp2)
        elif resp.positive:
            seed = resp.data[1:]  # 跳过子功能字节
            print(f"  种子: {seed.hex()}")
            print("  提示: 使用 'security <级别> <密钥hex>' 发送密钥")

    # ==================== 数据读写 ====================

    def do_readdid(self, arg):
        """读取DID数据\n用法: readdid <DID1> [DID2] ...\n示例: readdid F190\n      readdid F188 F189 F190"""
        if not self._check_activated():
            return

        if not arg.strip():
            print("  用法: readdid <DID> [DID2] ...")
            print("  常用DID:")
            for did, name in sorted(COMMON_DIDS.items()):
                print(f"    {did:04X} - {name}")
            return

        dids = []
        for d in arg.split():
            did_val = int(d, 16) if not d.startswith("0x") else int(d, 16)
            dids.append(did_val)

        did_names = [UDSClient.get_did_name(d) for d in dids]
        print(f"  读取DID: {', '.join(f'0x{d:04X}({n})' for d, n in zip(dids, did_names))}")

        resp = self.uds_client.read_data_by_identifier(*dids)
        self._print_response(resp)

        if resp.positive and resp.data:
            # 尝试ASCII解码
            raw = resp.data[2:] if len(resp.data) > 2 else resp.data
            try:
                ascii_str = raw.decode("ascii", errors="replace")
                if any(c.isprintable() for c in ascii_str):
                    print(f"  ASCII: {ascii_str}")
            except Exception:
                pass

    def do_writedid(self, arg):
        """写入DID数据\n用法: writedid <DID> <数据hex>\n示例: writedid F190 574441..."""
        if not self._check_activated():
            return

        args = arg.split(maxsplit=1)
        if len(args) < 2:
            print("  用法: writedid <DID> <数据hex>")
            return

        did = int(args[0], 16)
        data_record = bytes.fromhex(args[1].replace(" ", ""))

        print(f"  写入DID 0x{did:04X}, 数据: {data_record.hex()}")
        resp = self.uds_client.write_data_by_identifier(did, data_record)
        self._print_response(resp)

    # ==================== DTC操作 ====================

    def do_dtc(self, arg):
        """DTC操作\n用法: dtc <子命令>\n子命令:\n  read    - 读取所有DTC\n  count   - 读取DTC数量\n  clear   - 清除所有DTC\n  snapshot <DTC> - 读取DTC快照\n  extended <DTC> - 读取DTC扩展数据"""
        if not self._check_activated():
            return

        args = arg.split()
        if not args:
            print("  用法: dtc <子命令>")
            print("  子命令:")
            print("    read              - 读取所有DTC")
            print("    count [掩码]      - 读取DTC数量")
            print("    clear [DTC组]     - 清除DTC")
            print("    snapshot <DTC>    - 读取快照")
            print("    extended <DTC>    - 读取扩展数据")
            print("    supported         - 读取支持的DTC")
            return

        subcmd = args[0].lower()

        if subcmd == "read":
            mask = int(args[1], 16) if len(args) > 1 else 0xFF
            print(f"  读取DTC (状态掩码: 0x{mask:02X})...")
            resp = self.uds_client.read_dtc_report_by_status_mask(mask)
            self._print_response(resp)
            if resp.positive and resp.data:
                dtcs = UDSClient.parse_dtc_list(resp.data)
                if dtcs:
                    print(f"\n  共 {len(dtcs)} 个DTC:")
                    print("  " + "-" * 50)
                    for dtc in dtcs:
                        status_str = []
                        if dtc["status_bits"]["testFailed"]:
                            status_str.append("当前故障")
                        if dtc["status_bits"]["confirmedDTC"]:
                            status_str.append("已确认")
                        if dtc["status_bits"]["pendingDTC"]:
                            status_str.append("待定")
                        print(f"  DTC: {dtc['dtc']} | 状态: 0x{dtc['status']:02X} "
                              f"| {', '.join(status_str) or '无活动状态'}")
                    print("  " + "-" * 50)
                else:
                    print("  无DTC记录")

        elif subcmd == "count":
            mask = int(args[1], 16) if len(args) > 1 else 0xFF
            resp = self.uds_client.read_dtc_by_status_mask(mask)
            self._print_response(resp)
            if resp.positive and len(resp.data) >= 4:
                count = struct.unpack(">H", resp.data[2:4])[0]
                print(f"  DTC数量: {count}")

        elif subcmd == "clear":
            dtc_group = int(args[1], 16) if len(args) > 1 else 0xFFFFFF
            print(f"  清除DTC (组: 0x{dtc_group:06X})...")
            resp = self.uds_client.clear_dtc(dtc_group)
            self._print_response(resp)

        elif subcmd == "snapshot":
            if len(args) < 2:
                print("  用法: dtc snapshot <DTC hex>")
                return
            dtc = int(args[1], 16)
            record = int(args[2], 16) if len(args) > 2 else 0xFF
            resp = self.uds_client.read_dtc_snapshot_by_dtc(dtc, record)
            self._print_response(resp)

        elif subcmd == "extended":
            if len(args) < 2:
                print("  用法: dtc extended <DTC hex>")
                return
            dtc = int(args[1], 16)
            record = int(args[2], 16) if len(args) > 2 else 0xFF
            resp = self.uds_client.read_dtc_extended_data(dtc, record)
            self._print_response(resp)

        elif subcmd == "supported":
            resp = self.uds_client.read_supported_dtc()
            self._print_response(resp)

        else:
            print(f"  未知子命令: {subcmd}")

    # ==================== 通信控制 ====================

    def do_commctl(self, arg):
        """通信控制\n用法: commctl <on|off> [通信类型]\n通信类型: 1=普通, 2=NM, 3=普通+NM"""
        if not self._check_activated():
            return

        args = arg.split()
        if not args:
            print("  用法: commctl <on|off> [通信类型]")
            print("  通信类型: 1=普通通信, 2=NM通信, 3=普通+NM")
            return

        comm_type = int(args[1]) if len(args) > 1 else 0x01

        if args[0].lower() == "on":
            resp = self.uds_client.enable_rx_and_tx(comm_type)
        elif args[0].lower() == "off":
            resp = self.uds_client.disable_rx_and_tx(comm_type)
        else:
            print("  参数错误, 使用 on 或 off")
            return
        self._print_response(resp)

    def do_dtcctl(self, arg):
        """DTC设置控制\n用法: dtcctl <on|off>"""
        if not self._check_activated():
            return

        if not arg.strip():
            print("  用法: dtcctl <on|off>")
            return

        if arg.strip().lower() == "on":
            resp = self.uds_client.dtc_setting_on()
        elif arg.strip().lower() == "off":
            resp = self.uds_client.dtc_setting_off()
        else:
            print("  参数错误, 使用 on 或 off")
            return
        self._print_response(resp)

    # ==================== 例程控制 ====================

    def do_routine(self, arg):
        """例程控制\n用法: routine <start|stop|result> <例程ID hex> [参数hex]"""
        if not self._check_activated():
            return

        args = arg.split()
        if len(args) < 2:
            print("  用法: routine <start|stop|result> <例程ID> [参数hex]")
            return

        action = args[0].lower()
        routine_id = int(args[1], 16)
        option = bytes.fromhex(args[2]) if len(args) > 2 else b""

        if action == "start":
            resp = self.uds_client.start_routine(routine_id, option)
        elif action == "stop":
            resp = self.uds_client.stop_routine(routine_id, option)
        elif action == "result":
            resp = self.uds_client.request_routine_results(routine_id)
        else:
            print("  参数错误: start/stop/result")
            return
        self._print_response(resp)

    # ==================== IO控制 ====================

    def do_ioctl(self, arg):
        """IO控制\n用法: ioctl <DID> <控制参数> [控制状态hex]\n控制参数: 0=返回控制权, 1=复位默认, 2=冻结, 3=短期调整"""
        if not self._check_activated():
            return

        args = arg.split()
        if len(args) < 2:
            print("  用法: ioctl <DID> <控制参数> [控制状态hex]")
            print("  控制参数: 0=返回控制权给ECU")
            print("           1=复位为默认值")
            print("           2=冻结当前状态")
            print("           3=短期调整")
            return

        did = int(args[0], 16)
        control_param = int(args[1])
        control_state = bytes.fromhex(args[2]) if len(args) > 2 else b""

        resp = self.uds_client.io_control(did, control_param, control_state)
        self._print_response(resp)

    # ==================== 内存操作 ====================

    def do_readmem(self, arg):
        """按地址读取内存\n用法: readmem <地址hex> <长度>"""
        if not self._check_activated():
            return

        args = arg.split()
        if len(args) < 2:
            print("  用法: readmem <地址hex> <长度>")
            print("  示例: readmem 0x10000 256")
            return

        address = int(args[0], 16) if args[0].startswith("0x") else int(args[0], 16)
        size = int(args[1])

        resp = self.uds_client.read_memory_by_address(address, size)
        self._print_response(resp)
        if resp.positive and resp.data:
            self._hex_dump(resp.data[1:], address)  # 跳过addressAndLengthFormat

    def do_writemem(self, arg):
        """按地址写入内存\n用法: writemem <地址hex> <数据hex>"""
        if not self._check_activated():
            return

        args = arg.split(maxsplit=1)
        if len(args) < 2:
            print("  用法: writemem <地址hex> <数据hex>")
            return

        address = int(args[0], 16)
        data = bytes.fromhex(args[1].replace(" ", ""))

        resp = self.uds_client.write_memory_by_address(address, len(data), data)
        self._print_response(resp)

    # ==================== 原始数据发送 ====================

    def do_raw(self, arg):
        """发送原始UDS数据\n用法: raw <hex数据>\n示例: raw 1001\n      raw 22F190"""
        if not self._check_activated():
            return

        if not arg.strip():
            print("  用法: raw <hex数据>")
            print("  示例: raw 1001     (切换默认会话)")
            print("        raw 22F190   (读取VIN)")
            return

        try:
            data = bytes.fromhex(arg.strip().replace(" ", ""))
        except ValueError:
            print("  错误: 无效的hex数据")
            return

        print(f"  发送: {data.hex().upper()}")
        resp = self.uds_client.send_raw(data)
        self._print_response(resp)

    # ==================== 刷写功能 ====================

    def do_flash(self, arg):
        """固件刷写\n用法: flash <文件路径> <起始地址hex>\n示例: flash firmware.bin 0x00080000"""
        if not self._check_activated():
            return

        args = arg.split()
        if len(args) < 2:
            print("  用法: flash <文件路径> <起始地址hex>")
            return

        filepath = args[0]
        address = int(args[1], 16)

        if not os.path.exists(filepath):
            print(f"  错误: 文件不存在 - {filepath}")
            return

        filesize = os.path.getsize(filepath)
        print(f"  文件: {filepath}")
        print(f"  大小: {filesize} 字节")
        print(f"  地址: 0x{address:08X}")
        print(f"  正在请求下载...")

        # 请求下载
        resp = self.uds_client.request_download(address, filesize)
        if not resp.positive:
            print(f"  请求下载失败: {resp.nrc_description}")
            return

        # 解析最大块大小
        if len(resp.data) >= 2:
            length_format = resp.data[0]
            num_bytes = (length_format >> 4) & 0x0F
            if num_bytes > 0 and len(resp.data) >= 1 + num_bytes:
                max_block_size = int.from_bytes(resp.data[1:1 + num_bytes], 'big')
            else:
                max_block_size = 4096
        else:
            max_block_size = 4096

        # 减去块计数器开销
        chunk_size = max_block_size - 2
        print(f"  最大块大小: {max_block_size}, 数据块大小: {chunk_size}")

        # 传输数据
        block_counter = 1
        transferred = 0

        with open(filepath, "rb") as f:
            while transferred < filesize:
                chunk = f.read(chunk_size)
                if not chunk:
                    break

                resp = self.uds_client.transfer_data(block_counter & 0xFF, chunk)
                if not resp.positive:
                    print(f"\n  传输失败 @ block {block_counter}: {resp.nrc_description}")
                    return

                transferred += len(chunk)
                block_counter += 1
                progress = (transferred / filesize) * 100
                print(f"\r  进度: {progress:.1f}% ({transferred}/{filesize})", end="")

        print(f"\n  数据传输完成, 正在请求退出...")

        # 请求传输退出
        resp = self.uds_client.request_transfer_exit()
        self._print_response(resp)

    # ==================== 批量测试 ====================

    def do_scan(self, arg):
        """扫描ECU信息\n用法: scan [all|did|dtc]"""
        if not self._check_activated():
            return

        scan_type = arg.strip().lower() if arg.strip() else "all"

        if scan_type in ("all", "did"):
            print("\n  === 扫描常用DID ===")
            for did, name in sorted(COMMON_DIDS.items()):
                resp = self.uds_client.read_data_by_identifier(did)
                if resp.positive and resp.data:
                    raw = resp.data[2:]
                    try:
                        value = raw.decode("ascii", errors="replace").strip('\x00')
                    except Exception:
                        value = raw.hex()
                    print(f"  0x{did:04X} [{name}]: {value}")
                time.sleep(0.05)

        if scan_type in ("all", "dtc"):
            print("\n  === 扫描DTC ===")
            resp = self.uds_client.read_dtc_report_by_status_mask(0xFF)
            if resp.positive and resp.data:
                dtcs = UDSClient.parse_dtc_list(resp.data)
                if dtcs:
                    for dtc in dtcs:
                        print(f"  DTC: {dtc['dtc']} | 状态: 0x{dtc['status']:02X}")
                else:
                    print("  无DTC记录")
            else:
                print(f"  读取DTC失败")

    def do_script(self, arg):
        """执行脚本文件(每行一个命令)\n用法: script <文件路径> [延迟ms]"""
        args = arg.split()
        if not args:
            print("  用法: script <脚本文件> [命令间延迟ms]")
            return

        filepath = args[0]
        delay = int(args[1]) / 1000.0 if len(args) > 1 else 0.1

        if not os.path.exists(filepath):
            print(f"  错误: 文件不存在 - {filepath}")
            return

        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()

        print(f"  执行脚本: {filepath} ({len(lines)} 行)")
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            print(f"\n  [{i}] > {line}")
            self.onecmd(line)
            time.sleep(delay)

        print("\n  脚本执行完成")

    # ==================== 辅助命令 ====================

    def do_hex(self, arg):
        """Hex转换工具\n用法: hex <ascii字符串>  - ASCII转Hex\n      hex -d <hex数据>  - Hex转ASCII"""
        if not arg:
            print("  用法: hex <字符串>    ASCII转Hex")
            print("        hex -d <hex>   Hex转ASCII")
            return

        if arg.startswith("-d "):
            hex_str = arg[3:].replace(" ", "")
            try:
                data = bytes.fromhex(hex_str)
                print(f"  ASCII: {data.decode('ascii', errors='replace')}")
                print(f"  UTF-8: {data.decode('utf-8', errors='replace')}")
            except ValueError:
                print("  错误: 无效的hex数据")
        else:
            hex_str = arg.encode("ascii").hex()
            print(f"  Hex: {hex_str.upper()}")

    def do_clear(self, arg):
        """清屏"""
        os.system("cls" if os.name == "nt" else "clear")

    def do_quit(self, arg):
        """退出工具"""
        self._stop_tp()
        if self.doip_client and self.doip_client.is_connected:
            self.doip_client.disconnect()
        print("  再见!")
        return True

    def do_exit(self, arg):
        """退出工具"""
        return self.do_quit(arg)

    do_EOF = do_quit

    # ==================== 内部方法 ====================

    def _check_connected(self) -> bool:
        if not self.doip_client or not self.doip_client.is_connected:
            print("  错误: 未连接到DoIP网关, 请先使用 'connect' 命令")
            return False
        return True

    def _check_activated(self) -> bool:
        if not self._check_connected():
            return False
        if not self.doip_client.is_routing_activated:
            print("  错误: 路由未激活, 请先使用 'activate' 命令")
            return False
        return True

    def _stop_tp(self):
        if self.tp_thread:
            self.tp_thread.stop()
            self.tp_thread = None

    def _print_response(self, resp: UDSResponse):
        if resp.raw is None:
            print("  [无响应]")
            return

        if resp.positive:
            print(f"  [肯定响应] 原始数据: {resp.raw.hex().upper()}")
        else:
            print(f"  [否定响应] 原始数据: {resp.raw.hex().upper()}")
            print(f"             服务: 0x{resp.service_id:02X}, "
                  f"NRC: 0x{resp.nrc:02X} ({resp.nrc_description})")


def _hex_dump(self, data: bytes, start_addr: int = 0):
    """格式化hex dump输出"""
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(
            chr(b) if 32 <= b < 127 else "." for b in chunk
        )
        addr = start_addr + offset
        print(f"  {addr:08X}: {hex_part:<48} |{ascii_part}|")


def main():
    try:
        tool = DoIPTool()
        tool.cmdloop()
    except KeyboardInterrupt:
        print("\n  已中断")
        sys.exit(0)


if __name__ == "__main__":
    main()
