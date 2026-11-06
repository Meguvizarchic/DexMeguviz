# 静态 DEX 来源字节 v1

`dmg_snapshot_get_source_bytes_v1` 按 SourceSet 来源索引返回完整静态 DEX 的只读视图及长度。输入是压缩包时返回该来源解压后的 DEX 内容，不是 ZIP 原始内容；各来源及重复 occurrence 保持独立索引。此接口不写文件，不表示它与 DexKit 的 `exportDexFile(String)` 路径批量输出签名兼容，不证明运行时 loader 或已安装范围。

C 调用方必须在调用期间持有有效快照引用且遵循已有借用缓冲租约的不可变约定。成功返回的只读指针不分配或复制，维持到该快照引用释放为止；快照关闭后不能发起新的读取，但先前取得的视图在持有快照期间仍有效。调用方不得更改视图或在释放快照后使用它。`max_bytes` 必须为正，过小返回 BudgetExceeded；无效索引返回 InvalidArgument，关闭状态返回 Closed。失败输出清空，无部分结果。

Android `DexSourceExport.copy` 和 Kotlin `DexSourceExportExecution.copy` 在快照监视器内复制所选来源，返回独立的 Java byte[]，关闭快照后仍可持有。调用方必须提供正的 `maxBytes`，最多 Integer.MAX_VALUE；超限不分配或返回部分数组。Java 数组及其复制不属于 native 引擎的 owned-memory 预算，可能因 JVM 堆不足抛出 OutOfMemoryError。该方法是同步操作，应放到非 UI 线程。
