# DEX 调试局部变量生命周期观察（内部）

`debug::local_lifecycle` 按已有 checked `local_events` 的字节码顺序计算每个寄存器的显式状态转换；默认元数据打开和公开 ABI 不变。开始事件记录原始 uleb128p1 名称、类型、签名，结束保留最后显式身份，重启沿用它。未知名称或类型的零索引与“没有明确身份事件”分开；后者以 `last_identity_known=false` 表示。入口参数与 `this` 可能隐式存在，初始活跃状态为 Unknown，不从缺少开始事件推定错误。

连续结束可观察为 `end_after_known_end`，在已明确活跃后重启可观察为 `restart_while_known_live`；这些标志只是编码事件之间的局部关系，不判 DEX 损坏或 ART 的行为。新开始可替代之前显式状态。无 body 或 debug 信息返回空结果；不补出方法结束或结束序列时的生命周期终点，不建立类型、宽寄存器对、控制流或运行时对象语义。

所有状态与输出使用调用方 PMR，局部事件、opcode 与解码工作沿用 `Options` 的现有限额；映射与结果内存由调用方资源管理，不是 RSS 或 CPU 总预算。失败或分配异常不提交半结果。输入 bytes 和 facts 必须属于同一不可变已检查来源。依据 [Android DEX 格式](https://source.android.com/docs/core/runtime/dex-format) 的 debug_info 指令语义；本诊断不是完整 DEX verifier。

标准 CTest 注册 `debug_local_lifecycle` 固定事件和 PMR 失败检查；真实 DEX 独立字节对照由 `tests/debug_local_lifecycle/oracle.py` 单独运行，必须启用 Python 断言且写入新的输出路径。

## 显式 PC 边界分类

`Options.classify_local_boundaries` 默认 false。显式启用时，每条 local event 在其所属方法的完整 checked 指令解码结果中分类为可执行指令起点、指令内部、payload 起点、payload 内部或 `insns_size` 终点；没有覆盖信息或分类不能确定时为 Unknown。`boundary_classification_requested` 区分没有请求与已请求但仍 Unknown，`boundary_work` 统计分类查找的逻辑工作。`max_boundary_work` 是单次调用的分类工作上限，未启用或无事件时不消耗；不足返回预算错误，不返回半结果。独立 helper 要求输入为同一方法的完整、有序、非重叠 checked decoder 区间；找不到覆盖项或命中项自身无效时返回 Unknown，但不会全局验证输入，任意乱序或重叠区间不属于有效输入。等于 `insns_size` 不读取区间，仅表示数值端点，不证明生命周期结束或 ART 接受。

可选 `Options.cancelled` 在调用线程同步、协作检查，包含入口、checked 解码、调试 opcode 和生命周期转换；回调须 noexcept，数据和上下文在调用期间保持有效，且不得修改来源或重入共享资源。取消抛出 `DecodeError(cancelled)`，不会交付部分结果；检查点不承诺实时中断、完整系统 OOM 或对并发状态的外部原子快照。数据损坏、解码不支持、预算、取消和分配失败各自保留原错误类型，不转成空结果。默认 metadata-open 与旧未启用调用不收紧；这些分类不是对指令可达性、局部类型或 ART verifier 的断言。

参考 [Android DEX 格式](https://source.android.com/docs/core/runtime/dex-format) 对调试地址单位与 local opcode 的定义，以及 [Dalvik bytecode](https://source.android.com/docs/core/runtime/dalvik-bytecode) 对 16 位代码单元及 payload 的描述。真实 DEX 固定字节 oracle、合成边界/预算/取消和 PMR 故障样本仅限所列主机语料。
