# JNI use-event 图结果 v1（候选）

新增同步 `Snapshot.queryUseGraph(byte[])`、`SourceSetSnapshot.queryUseGraph(byte[])` 和 Kotlin `UseGraphQueryExecution.execute`。v1 wire 用于 C 编译器生成的 `query:v4:`、显式 `use_streaming` 的 `query:v9:` 以及 v16 目标符号事实图；这些旧 profile 的显式作用域和未支持能力返回 Unsupported。同步 v18 使用扩展 wire v2 并支持核心认可的显式 scope，详见 [JNI use-graph v2](jni-use-graph-v2.md)。既有 graph 方法与 ABI 不替换，旧方法仍拒绝事实图。异步事件批次另见 [独立 use-graph Job](jni-use-graph-job-v1.md)，该入口仅支持无 scope v4/v9。

`UseGraphResult` 按值复制 C ABI v2 的查询和关系状态、source/input、scope、profile、算子及每条行证据：entity/use tagged value、bindings/proof bindings 与路径、link 两端身份、relation witness 及对应身份。事件 `dexPc` 是 code unit，`targetDomain`、`targetIndex`、`extraProto` 原样保存，实体身份的 PC 与无额外 proto 使用 `0xffffffff`，来源 occurrence 与内容身份分开。计数和 Unknown 不折叠进 coverage/decision。结果及其文本独立于 native result 生命周期；路径访问返回副本。projection 仅约束主行，证据行沿 C ABI 获取完整允许字段。私有进程内 wire 不构成持久格式，超过 JNI 既有 8 MiB 等限制时拒绝。

每个输入均为不完整作用域；静态引用、source 身份和关系证明不表示 ART 装载、运行时绑定、bootstrap 语义或 BIL 支持。Windows JVM 固定样本结果只证明测试覆盖的范围，Android AAR、设备、所有查询组合和所有错误路径仍需独立验证。

另有独立 opt-in 的 [v4 顶层静态 slot 范围入口](jni-use-graph-scoped-v4.md)；上述原 `queryUseGraph` 对 v4/v9/v16 显式 scope 的拒绝保持不变。新入口只接收顶层 explicit scope 的v4，局部静态范围 Complete 不是 ClassLoader 或全应用完整性的证明。

