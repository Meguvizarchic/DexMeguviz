# JNI 静态反射与方法引用查询 v15

`Snapshot.queryReflectionMethodUses`、`SourceSetSnapshot.queryReflectionMethodUses` 和 Kotlin `ReflectionMethodUsesExecution.execute` 接受 UTF-8 JSON，仅支持明确声明 `reflection_flags_static` 与 `reflection_method_uses` 的直接 method_defs v15 查询。既有方法、实体和图入口的 profile 白名单保持不变；本入口拒绝其他 profile、显式作用域和未支持的能力。执行范围固定 incomplete，调用期间输入数组必须保持不变。

结果复用 `EntityResult`，保留静态方法身份、真实来源、QueryID、投影、Unknown、coverage 与 decision，输出 accessFlags 仍是原始 DEX 值。与实体桥相同的 JSON、work、results 和复制文本预算适用；异常或物化失败不交付半成品。实体查询结果不包含使用点 witness，不能推断 ART 反射、ClassLoader 绑定或运行时分派。

`startReflectionMethodUsesJob` 使用相同的 v15 限制与实体 Job 生命周期。批次均为 provisional，必须顺序消费到 EOS 后检查终态、Unknown、coverage、decision 和 reason。输入、复制、状态竞态和资源边界沿用 `jni-entity-query-v1.md` 和 `jni-job-method-v1.md`；不是总内存或时延承诺。

仅有隔离 Windows JVM 和固定 DEX 的验证不代表 Android/ART 或全部错误路径已验证。功能本身受 `reflection-method-uses-v15.md` 的静态模型和限定 profile 约束。
