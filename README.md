# 采集接口脱敏录制与离线重放

## 能力概览

`harvest/` 是采集客户端的**传输适配层**，在授权测试运行中录制真实请求交互，并支持之后完全离线重现同一批次。它不是保存成功日志后假装执行请求：重放器没有任何网络代码路径，未知请求显式失败，绝不访问公网。

三种模式通过 `harvest.open_transport(Mode, policy, pack_dir, ...)` 获取：

| 模式 | 行为 |
| --- | --- |
| `Mode.RECORD` | 包装内部传输（如 `SyntheticSource`），每个交换在写盘前按来源策略脱敏并符号化 |
| `Mode.REPLAY` | 仅从封包离线匹配响应；无网络回退，默认严格模式（每个已录交换都必须被调用） |
| `Mode.VERIFY` | 只校验：完整性、哈希、泄漏扫描、符号关联、当前策略兼容性，从不执行请求 |

## 脱敏与 fail-closed

脱敏规则全部来自 `SourcePolicy`，在写盘前生效：

- 认证头（`Authorization` 等，结构性强制）、声明的 Cookie 头替换为 `{"redacted": true}`，且不参与请求匹配；
- 联系人等声明的 JSON 字段递归替换为脱敏标记；
- 下载地址中的凭据（URL userinfo、声明的敏感查询参数如 `signature`）在字符串级别剥离；
- **策略不认识的敏感结构拒绝封包**：键名含 `token/secret/password/credential/signature/cookie/auth` 等提示、却未在策略中声明处理方式时，抛出 `SensitiveStructureError`，此时封包保持 `complete=false`，不会成为可用场景。

## 临时值符号化与跨请求关联

会话号、分页游标等临时值通过符号（如 `session`、`cursor`）关联：

- 录制时，响应中由 `Emitter` 声明的位置生成的值首次出现即绑定到符号，后续请求头/查询/体中的同一值全部替换为 `{"symbol": ...}`，磁盘上不存在原始临时值；
- 重放时，符号在响应物化阶段生成全新的假值（`REPLAY-SESSION-ledger-1` 等），后续请求必须携带本次运行生成的值；携带从未生成的值会得到明确的 `UnboundCorrelationError`，而不是错误匹配；
- 因此两次运行不需要生成相同的临时值，关联仍然成立。

## 内容匹配、乱序与重试预算

匹配键由来源、方法、路径、**有效查询参数**（忽略参数如 `trace_id` 不参与）和规范化结构化请求体组成，不按到达顺序取下一条，分页与详情请求可并发交错、乱序重放。

每个交换携带尝试预算：策略声明的可重复端点记录实际调用次数，其余端点预算为 1。重放时：

- 预算内的重复调用视为合法重试/多次调用；
- 超出预算抛出 `AttemptLimitError`，区分“录制的重试”与“额外调用”；
- 无匹配键时抛出 `UnknownRequestError`，附带最接近的候选、相似度和逐字段差异（方法/路径/查询/请求体）。

## 中断恢复与策略升级

- 每个交换文件和清单都通过临时文件 + 原子替换写入；清单在每次交换落盘后重写为 `complete=false`，仅在 `close()` 正常结束时翻转为 `complete=true`；
- 中断留下的半份材料无法被加载（`IncompletePackError`），`cleanup_partial()` 会删除不完整封包、或仅清理完整封包旁的 `.tmp` 残留，并返回可解释的清理报告；
- 清单记录 `policy_version` 与规则哈希。`accepts_versions` 不接受旧版本时，校验明确报告“旧材料必须重新录制”；兼容版本仅在规则哈希变化时给出警告。

## 目录结构

```
harvest/
  policy.py       来源策略、fail-closed 敏感结构检查与脱敏函数
  correlation.py  符号绑定表（录制侧自动绑定 / 重放侧惰性铸造假值）
  matching.py     结构化匹配键、相似度与差异解释
  recorder.py     录制传输（脱敏 + 符号化 + 原子落盘）
  replayer.py     严格离线重放传输（无网络原语）
  verify.py       只校验传输
  pack.py         封包格式、原子写入、清单、校验与中断清理
  rules.py        规则集合的确定性哈希
  errors.py       全部显式异常类型
offline_demo.py   本地假来源的端到端演示（全部为虚构主体与假令牌）
```

## 环境和运行

Python 3.11.10，仅依赖标准库，无需账号、第三方包或网络。在仓库根目录：

```sh
python3 -m unittest discover -s tests -v
python3 demo.py            # 原有授权与合成来源演示，保持不变
python3 offline_demo.py    # 录制/重放/校验全场景演示，输出结构化 JSON 报告
```

完整命令：

```sh
python3 -m unittest discover -s tests -v && python3 demo.py && python3 offline_demo.py
```

`offline_demo.py` 覆盖：会话值变化、乱序交错重放、敏感字段拒存、重试预算与合法多次调用、可解释的匹配失败、中断恢复与清理、策略升级复用判定、严格模式未用交换、只校验模式。状态写入系统临时目录，不污染仓库。

## 合成来源与素材

`synthetic_source.py` 提供带动态会话值和游标的假 HTTP 交互，不发送网络请求；`fixtures/exchanges.json` 展示敏感结构与场景清单，令牌与主体全部虚构。仓库中没有真实个人数据、真实凭据或选中代码。`service.authorized` 授权判断与根目录 `test_service.py` 保持原有接口不变。

## 能力边界

业务编排、跨多封包的流程决策与真实合作源对接不属于本传输层；封包只覆盖单次授权运行内的请求/响应交换。
