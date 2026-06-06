# DoIP 诊断工具

基于命令行的车载以太网 DoIP 诊断测试工具，支持 ISO 13400 (DoIP) + ISO 14229 (UDS) 协议。

## 功能特性

- **车辆发现**: UDP广播发现网络中的DoIP实体
- **连接管理**: TCP连接建立、路由激活、状态查询
- **诊断会话控制**: 默认/编程/扩展会话切换
- **安全访问**: 种子请求、密钥发送
- **DID读写**: 通过标识符读取/写入数据
- **DTC管理**: 读取、清除、快照、扩展数据
- **ECU复位**: 硬复位/软复位/KL15复位
- **通信控制**: 使能/禁止收发
- **例程控制**: 启动/停止/查询例程
- **IO控制**: 输入输出控制
- **内存读写**: 按地址读取/写入内存
- **固件刷写**: 支持文件传输刷写
- **TesterPresent保活**: 自动周期发送
- **批量扫描**: 一键扫描ECU信息和DTC
- **脚本执行**: 支持批量命令脚本
- **原始数据发送**: 支持任意UDS报文

## 环境要求

- Python 3.7+
- 无第三方依赖（纯标准库实现）

## 文件结构

```
doip-tool/
├── doip_client.py   # DoIP协议通信层
├── uds_service.py   # UDS诊断服务层
├── doip_tool.py     # 命令行交互界面(主入口)
└── README.md        # 使用说明
```

## 快速开始

```bash
python doip_tool.py
```

## 参数说明

### 必须配置的参数

| 参数 | 配置命令 | 说明 |
|------|----------|------|
| 目标IP | `config ip <地址>` | DoIP网关的IP地址，**必须设置**，也可在connect时直接传入 |
| 目标地址(TA) | `config ta <地址>` | 目标ECU的诊断地址，默认`0x0001`，**建议根据实际ECU确认** |

### 有默认值的参数（通常不用改）

| 参数 | 配置命令 | 默认值 | 说明 |
|------|----------|--------|------|
| 目标端口 | `config port <端口>` | 13400 | DoIP标准端口，一般不用改 |
| 源地址(SA) | `config sa <地址>` | 0x0E80 | 测试仪地址，一般不用改 |
| 超时时间 | `config timeout <秒>` | 5.0 | 响应等待超时 |
| 绑定网卡 | `config interface <IP>` | 自动选择 | PC有多个网卡时需指定 |
| 日志级别 | `config log <级别>` | WARNING | 排查问题时设为DEBUG |

### 关于"目标地址(TA)"和"诊断ID"

工具中的 `ta`（Target Address）就是平时说的**诊断地址/诊断ID**。每个ECU在车辆网络中有唯一的逻辑地址用于寻址，例如：
- 网关（GW）：`0x1000`
- 发动机ECU：`0x0001`
- 变速箱TCU：`0x0002`
- 车身控制器BCM：`0x0010`

具体值由车厂定义，可在诊断规范/CDD/ODX文件中查到。

### connect 命令用法

两种方式等效：

```
# 方式1：先配置再连接
DoIP> config ip 172.20.0.1
DoIP> connect

# 方式2：直接传参（会覆盖之前config的ip）
DoIP> connect 172.20.0.1

# 也可同时指定端口
DoIP> connect 172.20.0.1 13400
```

### 最简操作（只需知道网关IP）

如果目标ECU诊断地址恰好是默认的 `0x0001`：
```
DoIP> connect 172.20.0.1
DoIP> activate
DoIP> readdid F190
```

如果不是，先设置TA：
```
DoIP> config ta 0x1000
DoIP> connect 172.20.0.1
DoIP> activate
DoIP> readdid F190
```

## 使用流程

### 1. 发现车辆

```
DoIP> discover
DoIP> discover 5            # 设置5秒超时
DoIP> discover 3 192.168.1.255  # 指定广播地址
```

### 2. 配置参数

```
DoIP> config                # 查看当前配置
DoIP> config ip 192.168.1.1 # 设置目标IP
DoIP> config sa 0x0E80      # 设置源地址(Tester)
DoIP> config ta 0x0001      # 设置目标地址(ECU)
DoIP> config timeout 5      # 设置超时时间
DoIP> config interface 192.168.1.100  # 绑定网卡IP
DoIP> config log DEBUG      # 开启调试日志
```

### 3. 建立连接

```
DoIP> connect               # 使用已配置的IP连接
DoIP> connect 192.168.1.1   # 直接指定IP连接
DoIP> connect 192.168.1.1 13400  # 指定IP和端口
```

### 4. 激活路由

```
DoIP> activate              # 默认激活
DoIP> activate E0           # 中央安全激活
```

### 5. 诊断操作

连接并激活路由后，即可执行各种诊断命令。

## 命令详解

### 会话控制

```
DoIP> session 1             # 默认会话
DoIP> session 2             # 编程会话
DoIP> session 3             # 扩展诊断会话
```

### TesterPresent 保活

```
DoIP> tp                    # 发送一次TesterPresent
DoIP> tp start              # 启动自动保活(默认2s间隔)
DoIP> tp start 3            # 自定义间隔3秒
DoIP> tp stop               # 停止保活
```

### ECU 复位

```
DoIP> reset 1               # 硬复位
DoIP> reset 2               # KL15复位
DoIP> reset 3               # 软复位
```

### 安全访问

```
DoIP> security 1            # 请求Level 1种子
DoIP> security 1 0102030405 # 请求种子并发送密钥
```

### 读取 DID

```
DoIP> readdid               # 显示常用DID列表
DoIP> readdid F190          # 读取VIN码
DoIP> readdid F188 F189     # 同时读取多个DID
```

### 写入 DID

```
DoIP> writedid F190 5744414... # 写入DID数据(hex)
```

### DTC 操作

```
DoIP> dtc                   # 显示帮助
DoIP> dtc read              # 读取所有DTC
DoIP> dtc read 09           # 按掩码读取(当前+已确认)
DoIP> dtc count             # 读取DTC数量
DoIP> dtc clear             # 清除所有DTC
DoIP> dtc clear FFFFFF      # 清除指定DTC组
DoIP> dtc snapshot 062300   # 读取DTC快照
DoIP> dtc extended 062300   # 读取DTC扩展数据
DoIP> dtc supported         # 读取支持的DTC
```

### 通信控制

```
DoIP> commctl on            # 使能通信
DoIP> commctl off           # 禁止通信
DoIP> commctl off 3         # 禁止普通+NM通信
```

### DTC 设置控制

```
DoIP> dtcctl on             # 开启DTC记录
DoIP> dtcctl off            # 关闭DTC记录
```

### 例程控制

```
DoIP> routine start FF00            # 启动例程
DoIP> routine start FF00 01020304   # 带参数启动
DoIP> routine stop FF00             # 停止例程
DoIP> routine result FF00           # 查询例程结果
```

### IO 控制

```
DoIP> ioctl F000 0          # 返回控制权给ECU
DoIP> ioctl F000 3 01       # 短期调整
```

### 内存操作

```
DoIP> readmem 0x10000 256   # 读取内存
DoIP> writemem 0x10000 AABBCCDD  # 写入内存
```

### 固件刷写

```
DoIP> flash firmware.bin 0x00080000
```

刷写流程会自动完成：请求下载 → 分块传输 → 请求退出。

### 原始数据发送

```
DoIP> raw 1001              # 切换默认会话
DoIP> raw 22F190            # 读取VIN
DoIP> raw 1903FF            # 读取DTC
DoIP> raw 3101FF00          # 启动例程0xFF00
```

### 批量扫描

```
DoIP> scan                  # 扫描全部(DID+DTC)
DoIP> scan did              # 只扫描DID
DoIP> scan dtc              # 只扫描DTC
```

### 脚本执行

创建脚本文件（每行一个命令，#开头为注释）：

```
# test_script.txt
session 3
tp start
readdid F190
readdid F188
dtc read
tp stop
session 1
```

执行：

```
DoIP> script test_script.txt
DoIP> script test_script.txt 200   # 命令间延迟200ms
```

### 辅助工具

```
DoIP> hex Hello             # ASCII转Hex
DoIP> hex -d 48656C6C6F    # Hex转ASCII
DoIP> config                # 查看当前状态
DoIP> status                # 查询DoIP实体状态
DoIP> powermode             # 查询电源模式
DoIP> clear                 # 清屏
DoIP> quit                  # 退出
```

## 典型测试场景

### 场景1: 读取ECU基本信息

```
DoIP> connect 192.168.1.1
DoIP> activate
DoIP> session 3
DoIP> scan did
DoIP> quit
```

### 场景2: 清除DTC

```
DoIP> connect 192.168.1.1
DoIP> activate
DoIP> session 3
DoIP> dtc read
DoIP> dtc clear
DoIP> dtc read
DoIP> quit
```

### 场景3: 刷写固件

```
DoIP> connect 192.168.1.1
DoIP> activate
DoIP> session 2
DoIP> security 1 <密钥>
DoIP> flash firmware.bin 0x00080000
DoIP> reset 1
DoIP> quit
```

### 场景4: 长时间测试(保持会话)

```
DoIP> connect 192.168.1.1
DoIP> activate
DoIP> session 3
DoIP> tp start
DoIP> ...（执行各种测试命令）
DoIP> tp stop
DoIP> session 1
DoIP> quit
```

### 场景5: 从零开始读取VIN码

#### 第一步：硬件连接

1. 准备一台带以太网口的PC（或USB转以太网适配器）
2. 用以太网线将PC连接到车辆的以太网诊断接口
   - 部分车辆通过OBD-II接口的Pin 3/12 引出以太网
   - 部分车辆需要使用专用线束连接到ECU的以太网口

#### 第二步：配置PC网络

车载DoIP网关通常使用固定IP（如 `172.20.0.1` 或 `169.254.x.x`，具体看车辆文档）。

将PC以太网适配器设置为**静态IP**，与网关同网段：
- IP地址：例如 `172.20.0.100`（与网关同网段）
- 子网掩码：`255.255.0.0`（根据实际调整）
- 网关：留空

验证连通性：
```bash
ping 172.20.0.1
```
能ping通说明物理连接正常。

#### 第三步：启动工具

```bash
python doip_tool.py
```

#### 第四步：发现车辆（可选）

如果不确定网关IP和逻辑地址，用广播发现：
```
DoIP> discover
```
工具会列出所有发现的DoIP实体（含IP、逻辑地址、VIN）。

#### 第五步：配置并连接

```
DoIP> config ip 172.20.0.1    # 设置网关IP（替换为实际地址）
DoIP> config sa 0x0E80        # 测试仪源地址（一般不用改）
DoIP> config ta 0x0001        # 目标ECU逻辑地址（根据discover结果设置）
DoIP> connect                 # 建立TCP连接
DoIP> activate                # 激活路由
```

每一步都会有状态提示，确认成功后再继续下一步。

#### 第六步：读取VIN码

方式一：直接使用DID读取命令
```
DoIP> readdid F190
```

方式二：发送原始UDS报文
```
DoIP> raw 22F190
```

方式三：一键扫描（包含VIN在内的所有常用DID）
```
DoIP> scan did
```

成功响应示例：
```
  [肯定响应] 原始数据: 62F1904C464D585858585858585858585858
  ASCII: LFMXXXXXXXXXXXXXXX
```
其中17位ASCII字符串就是VIN码（DID `0xF190` 是ISO 14229标准定义的VIN标识符）。

#### 第七步：退出

```
DoIP> quit
```

#### 常见问题排查

| 现象 | 可能原因 | 解决方法 |
|------|----------|----------|
| TCP连接失败 | IP/网段配错、网线没插好 | 用ping确认网络连通 |
| 路由激活失败 | SA地址不在白名单 | 检查SA或尝试其他地址 |
| NRC 0x7F 会话不支持 | 默认会话禁止读取 | 先执行 `session 3` 切扩展会话 |
| NRC 0x33 安全访问拒绝 | DID需要解锁才能读 | 先执行安全访问解锁 |
| NRC 0x31 请求超出范围 | ECU不支持此DID | 确认ECU是否支持F190 |
| 无响应/超时 | TA地址不对 | 用discover确认目标地址 |

> 提示：大多数ECU在默认会话(0x01)就能读取VIN。如果失败，尝试切换到扩展会话：
> ```
> DoIP> session 3
> DoIP> readdid F190
> ```

## 注意事项

1. 确保PC与车辆在同一网段，建议使用静态IP配置
2. 默认DoIP端口为13400，部分车辆可能使用不同端口
3. 编程会话和安全访问的密钥需根据具体ECU确定
4. 刷写操作有风险，请确保固件文件和地址正确
5. 使用 `config log DEBUG` 可开启详细日志排查通信问题
6. TesterPresent保活在切换会话后建议开启，防止会话超时回退

## 协议参考

- ISO 13400-1/2/3: DoIP协议规范
- ISO 14229-1: UDS诊断服务定义
- ISO 15765-2: 网络层协议(DoIP中由TCP替代)
