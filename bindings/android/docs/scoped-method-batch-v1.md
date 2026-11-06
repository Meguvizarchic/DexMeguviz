# 显式输入范围内的同步多方法查询

`ScopedMethodBatchQuery.execute` 接受 Snapshot 或 SourceSetSnapshot、1–32 条直接 method-v1 QueryIR、缓存字节及工作上限；每条必须显式给出 `scope.slots`，且规范化后的 slot 列表必须完全一致。顺序不同但规范化一致可接受；缺失 scope、不同 slot、重复或未知 slot 明确失败。空列表选择零来源，资源-only slot 可选择零 DEX，一个多 DEX 输入展开全部 DEX occurrence。范围及复制结果在 snapshot 关闭后仍可读取。

此入口调用一次核心 `dmg_multi_execute_v1`，不是逐条模拟；只共享核心允许的已检查方法事实。执行前逐项核对规范 slot 和展开来源；执行后逐项核对实际来源序列、QueryID 与候选来源。返回 `scope` 是调用方声明的静态输入，不证明全部来源已访问，也不认证 APK 签名、安装或 ClassLoader；coverage 与 decision 仅针对这个静态范围。整体成功也必须检查每个结果的 executionStatus、coverage、decision 和 reason，ResultLimit 不等同完整成功。

上限沿用原非 scope `MethodBatchQuery`：每条 JSON 64 KiB、累计 JSON 1 MiB、单条最多 4096 结果及 1e8 work、累计最多 4096 行和 1,048,576 UTF-16 文本单元，缓存最多 16 MiB 与 1e8 work；结果 scope 的 slot 文本也计入总文本上限。整体执行/物化失败不交付部分批次，`MethodBatchQuery.Failure` 中的 status/failureIndex 区分失败；该同步接口须在后台使用，不提供取消、deadline 或 Job。原 `MethodBatchQuery` 继续拒绝 scope。

该候选仅有固定自建来源的 Windows JNI Java/Kotlin 和类/keep/API 检查，尚无完整 AAR、Android/ART、真实设备或真实性能证据；缓存命中本身不证明更快，也不证明 DexKit 全量兼容。
