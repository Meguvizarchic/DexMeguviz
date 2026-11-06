# 多 raw DEX JNI 来源集合草稿

`NativeEngine.openRawDexSet(byte[][], String[])` 在 JNI 中建立有序静态 SourceSet。桥接当前仅接受 1–8 项、总输入不超过 16 MiB；这是 JNI 限制，不是核心 SourceSet 的完整能力。每个 slot 是 1–128 个非空格可打印 ASCII，且同一集合中不能重复；角色固定 `raw-dex`、namespace 固定 `android-jni`。调用方须在同步调用返回前不修改数组、slot 数组和任何来源字节。只支持 RAW_DEX；APK、base/split 自动发现、加载器枚举和资源包不支持。所有输入长度及 slot 在分配来源缓存和复制前检查；任一来源无效、预算或资源失败均不发布部分 Snapshot。

`SourceSetSnapshot.info()` 按输入顺序返回复制的 `RawDexSourceInfo`：sourceIndex、inputIndex、slot、sourceSha256、contentId、occurrenceId、logicalDexId 和字节长度，以及集合 snapshotId；它们不再借用 native 内存。相同字节在不同 slot 保留不同 occurrence，相同 slot 与内容独立于排列保留 occurrence，snapshotId 对顺序敏感。单项集合和旧单 raw DEX 入口在同 slot/字节下使用同一身份域；旧 `Snapshot.info()` 与 `Snapshot.queryMethods()` 保持原有语义。

无论输入数量或结果如何，`sourceScopeComplete` 固定 false；此 API 不提供覆盖标志，也不从输入列表推断应用或 ClassLoader 全部来源。`SourceSetSnapshot.queryMethods` 同步执行直接 method-v1；显式 source scope、其他 profile 和桥接预算超限被拒绝。`QueryResult` 原有 executionStatus/coverage/decision/reason、queryId/snapshotId 等语义不变，不包含 witness，非独立验证证明；不完整范围内零命中不可证明不存在，两个不同可靠候选可证明 Ambiguous。每个多来源 `MethodCandidate` 从 C ABI `dmg_result_get_origin` 带有 sourceIndex、inputIndex、sourceSlot 和 occurrenceId；methodIndex 仅在对应来源的 DEX 内有意义。旧单源查询候选中新增来源字段为 sourceIndex/inputIndex=0，sourceSlot/occurrenceId=null，保留原已发布构造/查询行为。

查询 JSON、核心工作量、候选数和投影文本仍受原 `jni-method-query-v1` 上限约束；额外每条来源身份字符串及 Java 对象受最多 4,096 个候选和 128 字符 slot 约束，但 Java/JNI 复制和对象不在核心账本，不能据此断言进程总内存或时间有界。失败时 Java 不接收半成品；核心已发布 result-limit 的部分候选仍以非 OK executionStatus/Partial 显式标注。SourceSetSnapshot 的 info/query/close 单实例同步，使用同一 64 个快照注册表配额；必须显式 close，值对象关闭后仍可读。反射绕过 Java 锁的 native 查询/关闭仍遵循共享 owner 保活和核心 Closed 语义。

Kotlin `QueryExecution.execute(snapshot, query)` 同时接受单源 Snapshot 和多来源 SourceSetSnapshot，并保留各自 JNI 状态与来源范围；另有受限 method-v1 异步 Job，见 `jni-job-method-v1.md`。无跨调用 Query/Result、独立证据、ClassLoader/binder 或设备运行承诺。

另有显式指定格式的 raw DEX/APK 集合入口，见 `jni-source-set-v1.md`；旧 raw 入口的上述限制和身份语义保持不变。
