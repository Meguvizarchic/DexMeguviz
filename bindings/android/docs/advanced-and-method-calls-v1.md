# Android 高级实体查询与单方法调用事实

本批是现有静态能力的显式 Java/Kotlin/JNI 入口，不改变旧查询入口的版本判断，也不引入生产依赖。Kotlin 仍由宿主提供已授权的 2.4.21。所有输出为复制值，不持有已释放的 native buffer，不代表真实类加载、来源认证或运行时行为。

## Advanced 实体结果

`Snapshot` 和 `SourceSetSnapshot` 新增 `queryAdvanced(byte[])`、`startAdvancedJob(...)`；Kotlin 使用 `AdvancedQuery` 和 `AdvancedExecution`。QueryIR 仍由 native compiler 规范化；Kotlin 容器限定 64 KiB ASCII JSON，可通过 JSON escape/u16 表达 UTF-16。Java 原始字节入口也受既有 64 KiB、4096 候选和 1e8 work 上限。

入口准入 standalone v6 inherited_fields、v7 numeric_literals、v8 interface_fields、v11 interface_resolved 的实体主值及 metadata 关系形状。v7 可只有显式能力而无 numeric demand；其他高级组合仍拒绝。当前 Advanced wire **不接 use-relations 主值/绑定**；core 中可编译的 v6 use 图须继续视为该 Android 入口的 Unsupported，不能声称四个 profile 的任意形状均已接通。原 v1/v3/v4/v15/v18 等入口保持原合同。

`AdvancedResult` 保留输入、来源 occurrence、scope、QueryID/SnapshotID、执行/覆盖/决策、unknown、profile、可选图、实体、角色绑定/路径、连接及见证。直接查询明确 `hasGraph=false`，不伪造图；关系查询保留算子统计。v6 继承见证的 item/path/aux/branch/detail 全部传递；v8/v11 保留 interface item、branch/node/aux/detail，其中 v11 item 6 的定义选择与 v8 区分；v7 保留 width/kind/entity PC 和原始 64 位 bits，Java long 的负值不表示位模式损坏。各下标的来源/叶/分支局部含义沿用对应 core 合同。

Job 沿用有界队列、单消费者、NotReady/EOF、终态、取消和 AutoCloseable 模式。Batch 是 provisional，必须读取 `JobStatus` 终态；Java 交付失败会污染该消费流并请求取消，不能把后续 EOF 当成功。结果序列化限 8 MiB、累计 UTF-16 1,048,576 单元、100000 个记录项；限额是复制数据界限，不是 Java 堆或 RSS 上限。

## 直接选择 caller 的调用事实

`Snapshot.inspectMethodCalls(long methodRef)` 与 `SourceSetSnapshot.inspectMethodCalls(int sourceIndex,long methodRef)` 直接使用本地 method_ref→definition 目录，再收集 **这一方法** 的完整有序调用事实；不先扫描整个 DEX 再过滤 caller。两者都有追加 `maxRecords,maxWork,deadlineAfterMs` 的重载，默认 4096、1e8、0。可指定最多100000条、1e8 decoder validation work、最多86400000 ms截止时间。跨方法的辅助工作不能隐式扩充该操作的语义范围。

成功的 `MethodCallsResult` 带真实 SnapshotID、来源/归档身份、caller ordinal/ref/声明/代码偏移、hasBody/checked/codeUnits、validationWork 和复制的 owner/name/prototype。它不是 QueryIR 查询，因此不伪造 QueryID 或全局 decision。无体定义明确返回 `hasBody=false` 和空列表；只有外部引用、没有本地定义时返回 Unsupported；损坏、超限或截止失败抛 `NativeFailure`，不交付部分成功对象。

每行保留 PC、opcode、targetDomain/index、extraProto，以及存在时的 target owner/name/prototype 和 extraPrototype。普通 method_ref 域为2；polymorphic 的 method_and_proto 为3，保留额外原型；custom 的 call_site 为4，描述符为 null，不猜测 bootstrap 或运行时目标。方法内顺序严格递增。调用方可据单方法完整性实行 128/129 等业务阈值，但不能据此证明整个 APK 的候选范围、最终 owner 或 Hook 唯一性。

## 当前验证边界

Windows 主机 JNI 链接正式 iteration145 core；Java 17 与既有 Kotlin 2.4.21 编译器离线直编通过。v6/v7/v8/v11 各一个同步+Job连接样本通过（含v7高位64-bit模式和v11多定义choice见证）；单方法样本覆盖普通/多态/custom、第二来源 occurrence、无体、外部引用拒绝、超限无部分结果和复制值保留。固定 class/keep 注册映射核对通过。

首次 v11 wire 把 item上限按v8的5处理而拒绝choice=6，已按resolved标记分开修正；原代码和失败日志保留。注册检查原来只允许同名单方法，新增 inspectMethodCalls 两个明确重载后改为精确重载集合检查，不放宽其他方法。Gradle编译尝试遭遇本机 loopback 建连错误，原日志保留；本批没有新 AAR、Android双ABI、R8、全部JNI/Java ABI故障矩阵或设备/ART运行证据。不能将主机编译/样本称为完整 Android 验收。
