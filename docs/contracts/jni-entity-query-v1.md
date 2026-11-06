# 同步 JNI 直接实体查询

`Snapshot.queryEntities(byte[])` 和 `SourceSetSnapshot.queryEntities(byte[])` 接受 UTF-8 QueryIR JSON，Kotlin `QueryExecution.execute(snapshot, EntityQuery)` 调用同一入口。调用期间输入数组必须保持不变。仅接受 `query:v1:` 或 `query:v2:` 的直接七类 metadata 根；显式 scope、指令事实、关系图、继承、数值、v13 静态反射、v14 反射关系图或其他高级能力返回 Unsupported，不返回伪空结果，即使底层核心支持对应 profile 也不通过此桥。显式排序及 TopN 由对应核心 profile 决定。方法同步入口和 method-v1 Job 保留原有行为。`startEntityJob` 使用相同七类直接实体和范围限制。

来源范围始终 incomplete，`EntityResult` 分别保存 relation、executionStatus、coverage、decision、reason、visitedRows、totalRows、unknownRows、projectionMask、queryId 和 snapshotId。执行与覆盖不可从候选个数或对象存在推断；单候选 Unique 或零候选 Exists 不能证明完整应用中的唯一/不存在。结果和候选均为复制值，关闭快照后可读取；不包含独立 witness，也不代表运行时绑定。

每个 `EntityCandidate` 的 relation、sourceIndex、inputIndex、localIndex、referenceIndex、recordOffset 是静态本地身份；slot 和 occurrenceId 对单源和多源均从实际 origin 复制，APK 展开时 sourceIndex 不等于 inputIndex 是正常情况。所有无符号本地序号、偏移和 flags 以非负 Java long 表达。definitionOffset、accessFlags、codeOffset 是可空 Long：未知属性为 null；已知无方法体的 codeOffset 为 0，与引用行的未知 code 区别。owner、name、prototype、typeDescriptor、stringValue 在未投影或不适用于根时为 null，已投影空字符串保持空；UTF-16 码元逐个复制。

请求 JSON 上限 65,536 字节、max_results 不超过 4,096、max_work 不超过 100,000,000；每个同步结果或异步单批的输出投影文本总计不超过 1,048,576 个 UTF-16 码元，该上限不限制整个 Job 累计复制文本。核心可因其自身预算和解析限制更早拒绝。Java 对象、装箱及 JNI 临时复制不计入核心 Engine 账本，不能据这些限制推断进程总 RSS 或总延迟。任一 JNI 物化失败不会返回半成品结果。

仅 Windows 主机 JNI 测试和相应交叉构建的证据适用于其记录范围；它们不证明 Android 装载、ART、ClassLoader 或业务绑定。旧方法 ABI 保持，实体接口尚未承诺稳定公开版本。

## 实体异步批次

`Snapshot.startEntityJob`、`SourceSetSnapshot.startEntityJob` 和 Kotlin `QueryExecution.startEntityJob` 返回 `EntityJob`。参数与 method-v1 Job 相同；`next` 返回 `EntityJobPoll` 和复制的 `EntityResult`，每批为 Partial/NotApplicable、仅 provisional。顺序消费直到 EOS 后检查 `EntityJobStatus` 终态；EOS 或早期终态不单独证明已完整交付。取消、关闭、单消费者、失败后作废流及资源限制遵循 `jni-job-method-v1.md`。实体的 visitedRows/totalRows 与方法名称区分；状态仅终态有效。来源始终 incomplete，不包含见证、关系图或运行时绑定。对 JNI/JVM 副本与线程内存没有总 RSS 承诺。
