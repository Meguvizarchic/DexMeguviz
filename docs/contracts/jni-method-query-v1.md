# 同步 JNI 方法查询隔离草稿

`NativeEngine.Snapshot.queryMethods(byte[])` 同步接收 UTF-8 QueryIR JSON；调用期间不得修改输入数组。仅接受直接 method_defs 的 `query:v1` 身份域，不接受显式 source scope、其他实体/关系 profile 或批处理；未支持能力返回 `NativeFailure`，不会降级为空结果。查询不是可取消的后台 Job。Kotlin 可通过 `QueryExecution.execute(snapshot, query)` 调用这一有限桥；原无 snapshot 的入口仍不支持。

单源快照和有序多源 raw DEX 集合的 SourceSet 均固定 `scope_complete=false`；此接口拒绝显式子 scope，不能把所给输入提升为完整应用来源。`QueryResult` 保留 C 核心 executionStatus、coverage、decision、reason、访问计数、unknownRows、projectionMask、queryId、snapshotId。未完成范围内单候选 Unique 和零候选 Exists 不会变成确定结果；已观察到的 Exists 匹配仍可返回核心的 ProvenTrue。结果来自核心静态查询，**未携带 witness、不是独立验证证明**，更不代表 ART/ClassLoader、宿主业务或设备行为。调用者必须同时检查执行状态与覆盖范围，不得仅凭候选数量或 QueryResult 对象存在认定完整。

`MethodCandidate` 为 Java 自有值，methodIndex 是当前 DEX 的 method_id，flags 为原始 DEX flags，declarationOffset/codeOffset 是 DEX 字节偏移，codeOffset=0 表示无 code item；单来源的 sourceIndex/inputIndex 为 0、slot/occurrence 为 null；多来源返回每行实际 sourceIndex、inputIndex、slot 和 occurrenceId。未投影的 owner/name/prototype 是 null；已投影空字符串保持空。JNI `NewString` 按 UTF-16 码元复制结果，实际可出现的名称受 DEX 名称校验约束；查询输入可包含 NUL 和未配对代理项。结果与候选不暴露 native 指针，在返回后及快照关闭后仍可用。

桥接限制：JSON 最多 65,536 字节，核心 max_work 不超过 100,000,000，max_results 不超过 4,096，全部已投影文本不超过 1,048,576 个 UTF-16 单元；核心解析/预算可能更早拒绝。越界、非 method-v1、JNI/内存失败抛出 NativeFailure 或 JVM 异常；结果完整构造后才返回，不能返回部分伪成功。输入、Java 对象及 JNI 临时副本不计入核心 Engine 账本，这些上限不证明进程 RSS 或总延时受限。核心原生返回 result-limit 时必须保留其非 OK executionStatus、Partial 和 reason，不能将部分候选描述为完整。

每个快照 owner 持有 Engine 和快照；单次调用内 Query/Result 由 RAII 释放，Java 只接收复制值。一个 Java Snapshot 的 info/query/close 同步串行；不同对象可并发。JNI token lookup 获得 shared_ptr 后 owner 保活，原生绕过 Java 锁的并发 close 可能导致尚未开始的执行 Closed，或已获准执行继续；无跨调用原生 Query/Result 句柄。另有受限 method-v1 异步 Job，见 `jni-job-method-v1.md`；APK/base+split 发现、独立证据、binder、ClassLoader 世代和资源权限隔离仍未实现。Java 实例须显式 close。

需要对调用方声明的输入slot子集查询时，可使用独立的 [ScopedMethodQuery](jni-scoped-method-v1.md)；旧入口保持上述拒绝策略。
