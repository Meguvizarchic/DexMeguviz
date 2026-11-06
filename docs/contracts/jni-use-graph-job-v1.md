# JNI use-graph Job v1（隔离候选）

`Snapshot.startUseGraphJob`、`SourceSetSnapshot.startUseGraphJob` 和 `UseGraphQueryExecution.startJob` 是独立同步启动的异步任务入口；仅接受无顶层或节点 scope 的 `query:v4` 和 `query:v9`，拒绝 v16/v18、scope、其他 profile 和非 use 图，不扩展现有 graph/method/entity Job 或同步查询。输入数组在启动返回前必须保持不变，查询编译与 source 准备同步且不可由此 Job 取消。范围为不完整来源；profile、句柄与资源上限沿用 [method Job](jni-job-method-v1.md) 和 [use-graph](jni-use-graph-v1.md)：JSON 64 KiB、结果上限4096、max_work 100000000、每批最多4096、队列1–16、deadline 最多24小时，单批 wire 上限8 MiB。队列不限制调用方已取走的批次，复制、Java 对象和线程内存不在核心预算内。

`next` 返回 0（按值复制的 use graph provisional 批）、1（等待超时，不取消）、2（EOS，不等于成功）。每批 coverage 为 Partial、decision 为 NotApplicable；携带 QueryID/snapshot、来源 occurrence、event 的 DEX PC/域/索引、binding、proof、link 和 witness，profile 是生成该批时的快照，不是最终统计。读取并妥善处理全部批次直至 EOS，再检查 `status` 或 `waitFor` 的 terminal、lifecycle、executionStatus、coverage、decision、reason、unknown 和 error；Job 已终态仍可能有待消费批次，已交付批次在关闭后保持有效。终态 v2 另外分别保留 64 位 entity/method 访问计数及 event 数，未暴露最终算子 profile。状态不是未来并发交付成功的保证。

同一 Job 一个 next 消费者：锁从取批持续到 wire 序列化、Java 解码与 poll 对象构造；并发 next 明确拒绝。批次出队后复制/解码/包装失败会标记交付失败并请求取消，后续 next/status 不可当作成功；调用方丢弃该流。cancel、close 可与 next/wait 并发；关闭取消并移除句柄，正在 JNI 中的引用保活，可能在 close 后完成或返回 Closed。结果提交与取消优先级沿用核心执行契约。

v4 保持先完整求值再交付，不承诺扫描内早发；v9 仅核心允许的无排序 Exists/Unique 形状按已完成方法流式交付，其他形状仍先完整求值。两者按现有不同工作计费和异常顺序执行，不声称预算/错误时点等价。scope 声明不是全应用覆盖、类加载或运行时绑定。

目前仅直接 Windows JVM/JNI 固定样本和独立测试插桩验证，JVM/C 核心共享实现，并非独立 DEX 语义 oracle；故障注入不是系统 OOM。未验证完整调度、真实 R8、Android AAR/ART/设备或真实业务；人工固定用例不覆盖所有 scope、错误和图组合。新增精确 keep 规则保留 JNI 按名称访问的 `UseGraphResult.decode`，仅规则解析验证未代替 R8 运行。工具链隐式临时操作未追踪；测试脚本不显式删除文件。
