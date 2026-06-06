"""
UDS诊断服务模块 - 实现ISO 14229 UDS诊断服务
包含常用诊断服务的封装和NRC解析
"""

import logging
import struct
from enum import IntEnum
from typing import Optional, Tuple, List, Dict

from doip_client import DoIPClient

logger = logging.getLogger(__name__)


class UDSServiceID(IntEnum):
    """UDS服务ID定义 (ISO 14229-1)"""
    # 诊断和通信管理
    DIAGNOSTIC_SESSION_CONTROL = 0x10
    ECU_RESET = 0x11
    SECURITY_ACCESS = 0x27
    COMMUNICATION_CONTROL = 0x28
    TESTER_PRESENT = 0x3E
    ACCESS_TIMING_PARAMETER = 0x83
    SECURED_DATA_TRANSMISSION = 0x84
    CONTROL_DTC_SETTING = 0x85
    RESPONSE_ON_EVENT = 0x86
    LINK_CONTROL = 0x87
    # 数据传输
    READ_DATA_BY_IDENTIFIER = 0x22
    READ_MEMORY_BY_ADDRESS = 0x23
    READ_SCALING_DATA_BY_IDENTIFIER = 0x24
    READ_DATA_BY_PERIODIC_IDENTIFIER = 0x2A
    DYNAMICALLY_DEFINE_DATA_IDENTIFIER = 0x2C
    WRITE_DATA_BY_IDENTIFIER = 0x2E
    WRITE_MEMORY_BY_ADDRESS = 0x3D
    # DTC相关
    CLEAR_DIAGNOSTIC_INFORMATION = 0x14
    READ_DTC_INFORMATION = 0x19
    # 输入输出控制
    INPUT_OUTPUT_CONTROL = 0x2F
    # 例程控制
    ROUTINE_CONTROL = 0x31
    # 上传下载
    REQUEST_DOWNLOAD = 0x34
    REQUEST_UPLOAD = 0x35
    TRANSFER_DATA = 0x36
    REQUEST_TRANSFER_EXIT = 0x37
    REQUEST_FILE_TRANSFER = 0x38


class UDSSessionType(IntEnum):
    """会话类型"""
    DEFAULT = 0x01
    PROGRAMMING = 0x02
    EXTENDED_DIAGNOSTIC = 0x03


class UDSResetType(IntEnum):
    """ECU复位类型"""
    HARD_RESET = 0x01
    KEY_OFF_ON_RESET = 0x02
    SOFT_RESET = 0x03


class NRC(IntEnum):
    """否定响应码 (Negative Response Code)"""
    GENERAL_REJECT = 0x10
    SERVICE_NOT_SUPPORTED = 0x11
    SUB_FUNCTION_NOT_SUPPORTED = 0x12
    INCORRECT_MESSAGE_LENGTH = 0x13
    RESPONSE_TOO_LONG = 0x14
    BUSY_REPEAT_REQUEST = 0x21
    CONDITIONS_NOT_CORRECT = 0x22
    REQUEST_SEQUENCE_ERROR = 0x24
    NO_RESPONSE_FROM_SUBNET = 0x25
    FAILURE_PREVENTS_EXECUTION = 0x26
    REQUEST_OUT_OF_RANGE = 0x31
    SECURITY_ACCESS_DENIED = 0x33
    AUTHENTICATION_REQUIRED = 0x34
    INVALID_KEY = 0x35
    EXCEEDED_NUMBER_OF_ATTEMPTS = 0x36
    REQUIRED_TIME_DELAY_NOT_EXPIRED = 0x37
    SECURE_DATA_REQUIRED = 0x38
    UPLOAD_DOWNLOAD_NOT_ACCEPTED = 0x70
    TRANSFER_DATA_SUSPENDED = 0x71
    GENERAL_PROGRAMMING_FAILURE = 0x72
    WRONG_BLOCK_SEQUENCE_COUNTER = 0x73
    REQUEST_CORRECTLY_RECEIVED_RESPONSE_PENDING = 0x78
    SUB_FUNCTION_NOT_SUPPORTED_IN_ACTIVE_SESSION = 0x7E
    SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION = 0x7F
    VOLTAGE_TOO_HIGH = 0x92
    VOLTAGE_TOO_LOW = 0x93


# NRC中文描述
NRC_DESCRIPTIONS = {
    0x10: "通用拒绝",
    0x11: "服务不支持",
    0x12: "子功能不支持",
    0x13: "消息长度或格式不正确",
    0x14: "响应过长",
    0x21: "忙-重复请求",
    0x22: "条件不满足",
    0x24: "请求顺序错误",
    0x25: "子网无响应",
    0x26: "故障导致无法执行",
    0x31: "请求超出范围",
    0x33: "安全访问拒绝",
    0x34: "需要认证",
    0x35: "无效密钥",
    0x36: "超过尝试次数",
    0x37: "需要的时间延迟未到期",
    0x38: "需要安全数据",
    0x70: "上传/下载未接受",
    0x71: "传输数据暂停",
    0x72: "通用编程失败",
    0x73: "错误的块序列计数器",
    0x78: "请求正确接收-响应待定",
    0x7E: "当前会话不支持此子功能",
    0x7F: "当前会话不支持此服务",
    0x92: "电压过高",
    0x93: "电压过低",
}

# 常用DID定义
COMMON_DIDS = {
    0xF186: "当前诊断会话",
    0xF187: "零件号(备件)",
    0xF188: "ECU软件版本号",
    0xF189: "ECU软件版本日期",
    0xF18A: "供应商标识码",
    0xF18B: "ECU生产日期",
    0xF18C: "ECU序列号",
    0xF190: "VIN码",
    0xF191: "ECU硬件版本号",
    0xF192: "供应商ECU硬件版本号",
    0xF193: "供应商ECU软件版本号",
    0xF194: "供应商ECU软件版本日期",
    0xF195: "指纹信息",
    0xF197: "系统名称或ECU名称",
    0xF198: "维修店代码/Tester序列号",
    0xF199: "编程日期",
    0xF19D: "ECU安装日期",
    0xF19E: "诊断协议ID",
    0xF1A0: "短名称(ASCII)",
}


class UDSResponse:
    """UDS响应封装"""

    def __init__(self, raw_data: Optional[bytes]):
        self.raw = raw_data
        self.positive = False
        self.service_id = 0
        self.sub_function = 0
        self.nrc = 0
        self.data = b""
        self._parse()

    def _parse(self):
        if not self.raw or len(self.raw) == 0:
            return

        if self.raw[0] == 0x7F:
            # 否定响应
            self.positive = False
            if len(self.raw) >= 3:
                self.service_id = self.raw[1]
                self.nrc = self.raw[2]
        else:
            # 肯定响应
            self.positive = True
            self.service_id = self.raw[0] - 0x40
            self.data = self.raw[1:]

    @property
    def nrc_description(self) -> str:
        return NRC_DESCRIPTIONS.get(self.nrc, f"未知NRC(0x{self.nrc:02X})")

    def __repr__(self):
        if self.positive:
            return (f"肯定响应 [SID=0x{self.service_id:02X}] "
                    f"数据={self.data.hex()}")
        else:
            return (f"否定响应 [SID=0x{self.service_id:02X}] "
                    f"NRC=0x{self.nrc:02X} ({self.nrc_description})")


class UDSClient:
    """UDS诊断客户端 - 封装常用UDS诊断服务"""

    def __init__(self, doip_client: DoIPClient):
        self.doip = doip_client
        self.p2_timeout = 5.0  # P2 超时时间(秒)
        self.p2_star_timeout = 25.0  # P2* 超时时间(秒)

    def _send_request(self, data: bytes,
                      target_address: Optional[int] = None) -> UDSResponse:
        """发送UDS请求并返回响应"""
        success, msg, resp_data = self.doip.send_diagnostic_raw(
            data, target_address
        )
        if success and resp_data:
            return UDSResponse(resp_data)
        else:
            logger.error(f"诊断请求失败: {msg}")
            return UDSResponse(None)

    # ==================== 诊断会话控制 ====================

    def diagnostic_session_control(self, session_type: int) -> UDSResponse:
        """0x10 诊断会话控制"""
        data = bytes([UDSServiceID.DIAGNOSTIC_SESSION_CONTROL, session_type])
        return self._send_request(data)

    def enter_default_session(self) -> UDSResponse:
        """进入默认会话"""
        return self.diagnostic_session_control(UDSSessionType.DEFAULT)

    def enter_programming_session(self) -> UDSResponse:
        """进入编程会话"""
        return self.diagnostic_session_control(UDSSessionType.PROGRAMMING)

    def enter_extended_session(self) -> UDSResponse:
        """进入扩展会话"""
        return self.diagnostic_session_control(UDSSessionType.EXTENDED_DIAGNOSTIC)

    # ==================== ECU复位 ====================

    def ecu_reset(self, reset_type: int) -> UDSResponse:
        """0x11 ECU复位"""
        data = bytes([UDSServiceID.ECU_RESET, reset_type])
        return self._send_request(data)

    def hard_reset(self) -> UDSResponse:
        """硬复位"""
        return self.ecu_reset(UDSResetType.HARD_RESET)

    def soft_reset(self) -> UDSResponse:
        """软复位"""
        return self.ecu_reset(UDSResetType.SOFT_RESET)

    def key_off_on_reset(self) -> UDSResponse:
        """KL15复位"""
        return self.ecu_reset(UDSResetType.KEY_OFF_ON_RESET)

    # ==================== 安全访问 ====================

    def security_access_request_seed(self, level: int) -> UDSResponse:
        """0x27 安全访问 - 请求种子"""
        data = bytes([UDSServiceID.SECURITY_ACCESS, level])
        return self._send_request(data)

    def security_access_send_key(self, level: int, key: bytes) -> UDSResponse:
        """0x27 安全访问 - 发送密钥"""
        data = bytes([UDSServiceID.SECURITY_ACCESS, level + 1]) + key
        return self._send_request(data)

    # ==================== 读取数据 ====================

    def read_data_by_identifier(self, *dids: int) -> UDSResponse:
        """0x22 通过标识符读取数据"""
        data = bytes([UDSServiceID.READ_DATA_BY_IDENTIFIER])
        for did in dids:
            data += struct.pack(">H", did)
        return self._send_request(data)

    def read_vin(self) -> Tuple[bool, str]:
        """读取VIN码"""
        resp = self.read_data_by_identifier(0xF190)
        if resp.positive and len(resp.data) >= 19:
            vin = resp.data[2:19].decode("ascii", errors="replace")
            return True, vin
        return False, resp.nrc_description if not resp.positive else "数据长度不足"

    def read_ecu_software_version(self) -> Tuple[bool, str]:
        """读取ECU软件版本"""
        resp = self.read_data_by_identifier(0xF189)
        if resp.positive and len(resp.data) > 2:
            version = resp.data[2:].decode("ascii", errors="replace")
            return True, version
        return False, resp.nrc_description if not resp.positive else "数据长度不足"

    # ==================== 写入数据 ====================

    def write_data_by_identifier(self, did: int, data_record: bytes) -> UDSResponse:
        """0x2E 通过标识符写入数据"""
        data = bytes([UDSServiceID.WRITE_DATA_BY_IDENTIFIER])
        data += struct.pack(">H", did) + data_record
        return self._send_request(data)

    # ==================== DTC相关 ====================

    def clear_dtc(self, dtc_group: int = 0xFFFFFF) -> UDSResponse:
        """0x14 清除诊断信息(DTC)"""
        data = bytes([UDSServiceID.CLEAR_DIAGNOSTIC_INFORMATION])
        data += struct.pack(">I", dtc_group)[1:]  # 3字节DTC组
        return self._send_request(data)

    def read_dtc_by_status_mask(self, status_mask: int = 0xFF) -> UDSResponse:
        """0x19 01 按状态掩码读取DTC数量"""
        data = bytes([UDSServiceID.READ_DTC_INFORMATION, 0x01, status_mask])
        return self._send_request(data)

    def read_dtc_report_by_status_mask(self, status_mask: int = 0xFF) -> UDSResponse:
        """0x19 02 按状态掩码报告DTC"""
        data = bytes([UDSServiceID.READ_DTC_INFORMATION, 0x02, status_mask])
        return self._send_request(data)

    def read_dtc_snapshot_by_dtc(self, dtc: int,
                                 record_number: int = 0xFF) -> UDSResponse:
        """0x19 04 按DTC读取快照记录"""
        data = bytes([UDSServiceID.READ_DTC_INFORMATION, 0x04])
        data += struct.pack(">I", dtc)[1:]  # 3字节DTC
        data += bytes([record_number])
        return self._send_request(data)

    def read_dtc_extended_data(self, dtc: int,
                               record_number: int = 0xFF) -> UDSResponse:
        """0x19 06 按DTC读取扩展数据"""
        data = bytes([UDSServiceID.READ_DTC_INFORMATION, 0x06])
        data += struct.pack(">I", dtc)[1:]
        data += bytes([record_number])
        return self._send_request(data)

    def read_supported_dtc(self) -> UDSResponse:
        """0x19 0A 读取支持的DTC"""
        data = bytes([UDSServiceID.READ_DTC_INFORMATION, 0x0A])
        return self._send_request(data)

    # ==================== 通信控制 ====================

    def communication_control(self, control_type: int,
                              comm_type: int) -> UDSResponse:
        """0x28 通信控制"""
        data = bytes([UDSServiceID.COMMUNICATION_CONTROL,
                      control_type, comm_type])
        return self._send_request(data)

    def enable_rx_and_tx(self, comm_type: int = 0x01) -> UDSResponse:
        """使能接收和发送"""
        return self.communication_control(0x00, comm_type)

    def disable_rx_and_tx(self, comm_type: int = 0x01) -> UDSResponse:
        """禁止接收和发送"""
        return self.communication_control(0x03, comm_type)

    # ==================== DTC设置控制 ====================

    def control_dtc_setting(self, setting_type: int) -> UDSResponse:
        """0x85 DTC设置控制"""
        data = bytes([UDSServiceID.CONTROL_DTC_SETTING, setting_type])
        return self._send_request(data)

    def dtc_setting_on(self) -> UDSResponse:
        """开启DTC记录"""
        return self.control_dtc_setting(0x01)

    def dtc_setting_off(self) -> UDSResponse:
        """关闭DTC记录"""
        return self.control_dtc_setting(0x02)

    # ==================== TesterPresent ====================

    def tester_present(self, suppress_response: bool = False) -> UDSResponse:
        """0x3E TesterPresent"""
        sub = 0x80 if suppress_response else 0x00
        data = bytes([UDSServiceID.TESTER_PRESENT, sub])
        if suppress_response:
            self.doip.send_diagnostic_raw(data)
            resp = UDSResponse(bytes([0x7E, 0x00]))
            resp.positive = True
            return resp
        return self._send_request(data)

    # ==================== 例程控制 ====================

    def routine_control(self, control_type: int, routine_id: int,
                        option_record: bytes = b"") -> UDSResponse:
        """0x31 例程控制"""
        data = bytes([UDSServiceID.ROUTINE_CONTROL, control_type])
        data += struct.pack(">H", routine_id) + option_record
        return self._send_request(data)

    def start_routine(self, routine_id: int,
                      option_record: bytes = b"") -> UDSResponse:
        """启动例程"""
        return self.routine_control(0x01, routine_id, option_record)

    def stop_routine(self, routine_id: int,
                     option_record: bytes = b"") -> UDSResponse:
        """停止例程"""
        return self.routine_control(0x02, routine_id, option_record)

    def request_routine_results(self, routine_id: int) -> UDSResponse:
        """请求例程结果"""
        return self.routine_control(0x03, routine_id)

    # ==================== IO控制 ====================

    def io_control(self, did: int, control_param: int,
                   control_state: bytes = b"") -> UDSResponse:
        """0x2F 输入输出控制"""
        data = bytes([UDSServiceID.INPUT_OUTPUT_CONTROL])
        data += struct.pack(">H", did)
        data += bytes([control_param]) + control_state
        return self._send_request(data)

    # ==================== 下载/上传 ====================

    def request_download(self, memory_address: int, memory_size: int,
                         compression: int = 0x00,
                         encrypting: int = 0x00) -> UDSResponse:
        """0x34 请求下载"""
        data_format = (compression << 4) | encrypting
        # 计算地址和大小的字节长度
        addr_len = (memory_address.bit_length() + 7) // 8
        size_len = (memory_size.bit_length() + 7) // 8
        addr_and_len_format = (size_len << 4) | addr_len

        data = bytes([UDSServiceID.REQUEST_DOWNLOAD,
                      data_format, addr_and_len_format])
        data += memory_address.to_bytes(addr_len, 'big')
        data += memory_size.to_bytes(size_len, 'big')
        return self._send_request(data)

    def transfer_data(self, block_counter: int,
                      transfer_data: bytes) -> UDSResponse:
        """0x36 传输数据"""
        data = bytes([UDSServiceID.TRANSFER_DATA, block_counter])
        data += transfer_data
        return self._send_request(data)

    def request_transfer_exit(self) -> UDSResponse:
        """0x37 请求传输退出"""
        data = bytes([UDSServiceID.REQUEST_TRANSFER_EXIT])
        return self._send_request(data)

    # ==================== 内存读写 ====================

    def read_memory_by_address(self, address: int, size: int) -> UDSResponse:
        """0x23 按地址读取内存"""
        addr_len = (address.bit_length() + 7) // 8
        size_len = (size.bit_length() + 7) // 8
        addr_and_len_format = (size_len << 4) | addr_len

        data = bytes([UDSServiceID.READ_MEMORY_BY_ADDRESS,
                      addr_and_len_format])
        data += address.to_bytes(addr_len, 'big')
        data += size.to_bytes(size_len, 'big')
        return self._send_request(data)

    def write_memory_by_address(self, address: int, size: int,
                                memory_data: bytes) -> UDSResponse:
        """0x3D 按地址写入内存"""
        addr_len = (address.bit_length() + 7) // 8
        size_len = (size.bit_length() + 7) // 8
        addr_and_len_format = (size_len << 4) | addr_len

        data = bytes([UDSServiceID.WRITE_MEMORY_BY_ADDRESS,
                      addr_and_len_format])
        data += address.to_bytes(addr_len, 'big')
        data += size.to_bytes(size_len, 'big')
        data += memory_data
        return self._send_request(data)

    # ==================== 辅助功能 ====================

    def send_raw(self, raw_bytes: bytes) -> UDSResponse:
        """发送原始UDS数据"""
        return self._send_request(raw_bytes)

    @staticmethod
    def parse_dtc_list(response_data: bytes) -> List[Dict]:
        """解析DTC列表 (19 02响应)"""
        dtcs = []
        if len(response_data) < 3:
            return dtcs

        # 跳过子功能和状态可用性掩码
        dtc_data = response_data[2:]
        i = 0
        while i + 3 < len(dtc_data):
            dtc_high = dtc_data[i]
            dtc_mid = dtc_data[i + 1]
            dtc_low = dtc_data[i + 2]
            status = dtc_data[i + 3]

            dtc_number = (dtc_high << 16) | (dtc_mid << 8) | dtc_low
            dtc_str = f"{dtc_high:02X}{dtc_mid:02X}{dtc_low:02X}"

            dtcs.append({
                "dtc": dtc_str,
                "dtc_number": dtc_number,
                "status": status,
                "status_bits": {
                    "testFailed": bool(status & 0x01),
                    "testFailedThisOperation": bool(status & 0x02),
                    "pendingDTC": bool(status & 0x04),
                    "confirmedDTC": bool(status & 0x08),
                    "testNotCompletedSinceLastClear": bool(status & 0x10),
                    "testFailedSinceLastClear": bool(status & 0x20),
                    "testNotCompletedThisOperation": bool(status & 0x40),
                    "warningIndicatorRequested": bool(status & 0x80),
                }
            })
            i += 4

        return dtcs

    @staticmethod
    def get_did_name(did: int) -> str:
        """获取DID名称"""
        return COMMON_DIDS.get(did, f"未知DID(0x{did:04X})")
