# JNI method-v1 Job 和临时批次

`Snapshot.startMethodJob` 与 `SourceSetSnapshot.startMethodJob` 接收直接 method-v1 UTF-8 QueryIR JSON。只接受 `query:v1:`、无显式 source scope，拒绝其他 profile；来源范围固定 incomplete。输入不得在同步启动返回前修改。JSON、max_work、max_results 与同步查询的 JNI 上限一致；batchSize 为 1–4096，maxQueuedBatches 为 1–16，deadlineAfterMs 为 0–86400000（0 表示没有 deadline）。启动前编译及来源构建是同步的、不可由本 Job 取消。

`Job.next(timeoutMs)` 限于 0–60000 ms，返回 `JobPoll.kind`：0 表示一个 `batch`，1 表示等待超时，2 表示队列已结束。等待超时不取消任务，队列结束不等于成功。每个批次以 `QueryResult` 和自有 `MethodCandidate` 值复制；coverage 为 Partial、decision 为 NotApplicable，且只表示 provisional 候选。多个来源按真实 sourceIndex/inputIndex/slot/occurrence 复制，单源沿用同步入口的兼容字段；无 witness，不是独立证明。每批投影文本受原 JNI 上限约束；Java/JNI 副本与线程内存不在核心账本，不据此承诺 RSS、整个 Job 的总副本上限或硬实时。

消费者须先顺序读取批次直到 `JobPoll.kind == 2`，再调用 `status()` 或 `waitFor(timeoutMs)` 检查终态；后者限于 0–60000 ms。终态以 `terminal` 标志、lifecycle、executionStatus、coverage、decision、reason、candidateCount、unknownRows 和 error 一起判断，不能用收到的行数或 EOS 替代。Job 可以在尚有已排队批次时终止，故单次成功状态不能证明批次已经完整交付。wait 超时返回当前非终态快照，不取消。未完成时其他状态字段不作最终判断。既有 ResultLimit、取消与终态优先级由核心契约决定，已交付的 Batch 不因取消回撤。

同一 Job 只允许一个并发 `next` 调用；其他并发 next 明确抛 `IllegalStateException`。`next` 与 `waitFor` 不持 Java Job 锁，另一个线程可调用 `cancel()` / `close()`；关闭移除句柄并请求取消，已进入原生调用的线程以共享所有权保活，可能在 close 返回后完成或报告 Closed。快照关闭不撤回已准入 Job；复制的批次在 Job 和快照关闭后仍有效。任意批次复制或交付失败时取消该 Job 并将流标为失败，不能再把它当成完整结果；调用者应丢弃该流并关闭。状态调用在核心返回后复查该标志，其成功结果只表示该复查时未观察到交付失败；并发消费者之后仍可能失败，状态调用不与未来批次交付事务化。只有顺序消费、读取 EOS 后检查终态，且中途没有交付异常，才能判断已取回的完整批次集合。

全进程最多64个已创建或启动中的 Job 句柄；关闭后仍被在途 JNI 调用持有的 Job 继续占用配额，直到最后原生引用释放。每个 Engine 的活动 Job 上限独立，默认 4。显式 close 请求取消并最终 join/释放 worker；消费者持有 Job 句柄时，背压可能暂停生产者，deadline/取消可解除等待。窗口关闭/取消与状态提交的具体线性化及非抢占区域由 `execution-v1.md` 规定，不承诺 JNI 对所有分配失败或异常锁路径的完整验证。

测试仅覆盖隔离 Windows JVM/JNI、固定 DEX/APK 与已记录并发场景；生产 Android 装载、设备、ClassLoader/binder、独立见证、所有调度/内存失败组合及完整 JNI Query/Batch API 仍未验证。

显式输入slot子范围可使用独立的 [ScopedMethodQuery Job](jni-scoped-method-v1.md)；旧Job入口保持上述拒绝策略。
