# Android 静态类注解查询 v24

`ClassAnnotationQuery.execute(snapshot, queryJson)` 提供单来源或 SourceSet 的同步 v24 类注解查询，返回复制的 `NativeEngine.EntityResult`；Java 调用在 snapshot 监视器内完成，Kotlin 可直接调用同一 Java 入口。输入必须显式声明 `class_annotation_static`，限制为直接 class_defs、非 scope，并使用核心允许的类型、可见性及可选顶层 VALUE_INT 条件。核心支持显式 slot scope，但本入口明确拒绝该形状；不自动扩大或重写输入范围。

返回的 `unknownRows`、coverage、decision、reason 和 executionStatus 必须一并检查；缺省注解元素会产生 Unknown 而非自动判为无匹配。结果包含来源 slot、source/input 索引和 occurrence；这些只描述显式静态输入，不认证运行时 loader 或证明全应用覆盖。错误、预算超限、关闭及未知形状按现有 JNI 状态传播；旧实体查询桥和旧 Job 的支持范围不变。

遵循既有 64 KiB 查询、4096 结果、1e8 work 和累计文本上限；底层 v24 不支持的方法/字段/参数注解、数组/嵌套匹配、排序、top-n 及高级 profile 组合不会被桥接。比较缺省语义为项目保守设计，不声称 DexKit 逐项等价。

当前候选仅通过 Windows JNI 的 Java/Kotlin 和 R8 classfile 样本、R8 DEX 方法结构及双 ABI 交叉链接/符号核对；尚无从本次完整源码重构的 AAR、Android/ART、设备、业务或性能证据。

`ClassAnnotationQuery.startJob(snapshot, queryJson, batchSize, maxQueuedBatches, deadlineAfterMs)` 复用 `NativeEngine.EntityJob`，仅支持非 scope v24；单来源和 SourceSet 均可调用。批次是暂定结果，EOF 不等于成功；调用方须检查 terminal、executionStatus、coverage、decision 和 unknownRows。取消、关闭、单消费者、背压和 Java 批次交付失败遵循既有 EntityJob 合同。该 Job 不认证来源或 loader，显式 scope Job 暂不支持。
