# Android 同步多方法查询（候选）

`MethodBatchQuery.execute` 接受 Snapshot/SourceSetSnapshot、1–32 条 QueryIR JSON 和调用方明确指定的缓存字节/工作上限，按输入顺序返回 `Result.get(i)` 对应的 `NativeEngine.QueryResult`。仅接受无显式 scope 的直接 `query:v1:` 方法查询，包括其已支持的排序/TopN；旧方法和 Job 入口不改变。调用期间所有输入字节保持不变，调用同步执行，应在后台线程运行；此入口不提供取消或 deadline。

真实调用 `dmg_multi_execute_v1`；按核心合同，执行/物化失败不返回任何批次结果，已耗费的工作不会撤回。`MethodBatchQuery.Failure` 的 `status`、`failureIndex` 和 `errorOffset` 保存能归因的 native 失败，索引 -1 表示无法归因；多个规则评估和物化的失败优先级不保证与逐条执行相同。Java 分配、JNI 调用或复制期间的 JVM 异常及已有 NativeFailure 可原样传播，此类异常不保证提供规则索引，不得把它们解释为完整批次。整体成功仍须逐项查看 executionStatus、coverage、decision 和 reason；例如 ResultLimit 是携带预算状态的单项结果，不是完整成功。Android 来源仍为不完整静态 scope，结果不认证 loader。

每条输入最多 64 KiB，总输入最多 1 MiB；单条最多 4096 结果和 1e8 逻辑 work；全部输出候选累计最多 4096、候选 owner/name/prototype 以及来源槽/occurrence 的累计文本最多 1,048,576 UTF-16 单元。cacheBytes 为 0..16 MiB，maxCacheWork 为 0..1e8；任一为零时核心禁用共享。上限是显式复制与计费范围，不是 JVM 堆、RSS 或绝对 CPU 用量的保证。核心受控内存会在结果构造前分配并可能受预算失败；超过聚合上限时已做的工作不回滚。

Profile 是核心提供的缓存观察：physicalCollects 仅涵盖接入缓存的路径，不是总解码次数；cacheHits、cacheBuilds 和 cacheWorkCharged 等不能单独证明加速或与逐条执行具有相同峰值/错误顺序。支持哪些 demand/profile 共享及回退，遵循 `docs/contracts/multi-query-c-v1.md`。本候选仅经固定 Windows JNI/Kotlin 样本和类/keep/合成导出审计；未证明 Android/ART、真实 APK、所有故障或性能优势。
