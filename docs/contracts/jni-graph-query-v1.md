# JNI v3 / v14 metadata 关系图

`Snapshot.queryGraph(byte[])`、`SourceSetSnapshot.queryGraph(byte[])` 与 `GraphQueryExecution.execute(snapshot, ByteArray)` 接受 UTF-8 QueryIR JSON，期间输入数组必须保持不变。此入口接受 `query:v3:` 与显式声明两种 reflection 能力的 `query:v14:` 纯 metadata 的 scan/filter/union/distinct/label/group_by_owner/join/semi_join，保留核心对应意图与排序；源快照固定 incomplete。显式 scope（包括任一子 Scan scope）、指令事实、v4/v6–v13 等其他 profile、非图查询和未知能力明确返回 Unsupported。Kotlin 也提供限定范围的 [类型化构造器](kotlin-graph-dsl-v1.md)；能生成 JSON 或取得结果并不代表整个应用范围完整。

`GraphResult` 复制核心实体、输入与来源身份、scope、查询及算子统计、每行 binding、proof binding、路径、links 与 relation witness；结果在快照关闭后仍可读取。根实体仅保留请求的投影，binding/proof 的实体文本按对应类型完整复制。非适用或未投影文本为 null，已投影空字符串为 ""；UTF-16 code units 保留 NUL、代理对和孤立代理项。`Source.archiveEntryName` 对 raw DEX 为 null，`archiveEntryIndex` 为无符号 long 的 0xffffffff；对应已有 JNI 的 int -1。APK 条目保留真实 sourceIndex、inputIndex、slot、occurrence 与中央目录索引，不能按 inputIndex 猜 sourceIndex。数值证据的 native uint32 哨兵保留为 0xffffffff long；调用方不得把它误当有效局部 ID。

输入 JSON 上限 65,536 字节，max_results 不超过 4096、max_work 不超过 100,000,000。整个结果的 wire 上限为 8 MiB，复制文本合计最多 1,048,576 UTF-16 码元，候选/绑定/证明/links/witness 合计最多 100,000 项；超限或任何物化失败不会交付半成品。core 账本不覆盖 JNI 字节缓冲、Java 对象或应用线程；以上不是总 RSS 承诺。wire 仅为本库私有版本协议，不是持久化或跨版本 API。

固定 DEX 的 Java/Kotlin Windows JVM JNI 测试和 CLI 结构对照范围见验证记录；这不是 Android 装载、ART、ClassLoader、业务绑定或独立第三方见证验证。v14 的反射 flags 仅为静态候选匹配，返回实体 accessFlags 仍是原始 DEX flags；不存在定义或未建模事实保守 Unknown。该入口不声称全面关系 IR、使用事实或 ART 反射行为。


## 图异步批次

`Snapshot.startGraphJob`、`SourceSetSnapshot.startGraphJob` 和 `GraphQueryExecution.startGraphJob` 受同步图入口相同 profile、来源、输入上限限制。参数、超时、取消、关闭及单消费者约束与 `jni-job-method-v1.md` 一致。`GraphJob.next` 返回 `GraphJobPoll`：0 为 `GraphResult` 批次，1 为超时，2 为流结束；每批为 Partial/NotApplicable 的 provisional 结果。必须顺序读取到 EOS，再检查 `GraphJobStatus` 的 terminal、executionStatus、coverage、decision、reason 等；终态可能先于队列清空，不以 EOS 或候选数代替终态。

每批独立保留 query/snapshot/来源、根实体、绑定、证明绑定、路径、链接和见证及该批创建时的 profile；profile 是批次快照而非最终全局计数。每批沿用图 wire 的 8 MiB、文本及条目上限，不限制整个 Job 累计输出。原生侧持有单消费者锁直到字节复制、Java 解码和 poll 构造结束；消耗批次后任一步失败会标记流失败并请求取消，后续 next/status 不可视作成功。关闭或取消与在途调用的生命周期和状态复查时点遵循 method Job 契约。

此接口目前只提供终态基本状态，不提供最终 Job 图算子 profile；不支持 use、v6–v13 高级 profile、显式 scope 或运行时绑定。复制缓存、Java 解码和线程内存仍不计核心 Engine 总账本。本地 JVM 固定测试及 JNI 交叉编译不能证明 Android/ART 或真实 JVM OOM。


