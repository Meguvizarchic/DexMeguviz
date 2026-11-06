# 选中范围的快速 DEX 查询草案

`FastDexQuery.compile(queries, captureCalls)` 将 1–16 条受支持的 QueryIR 编译为可关闭计划；`Plans.scan(dex, InputAssumption.CALLER_ASSERTS_VALID_SORTED_DEX, limits)` 同步查询一份 DEX。计划和输入数组在调用返回前不得修改。结果为 Java 值副本；多来源调用方须在外层为每份结果保留 APK 槽位、DEX 条目和 occurrence，不能跨 DEX 仅以方法索引去重。

该入口是显式 opt-in。调用方须保证输入在调用期间不可变，并断言 DEX 结构有效、ID 表符合排序规则；它只检查查询触及的元数据和选中方法体，不是完整 DEX verifier，也不认证 APK、ClassLoader 或 ART 实际装载字节。每条规则的 `coverage()` 始终为 partial，`callerAssertedExhaustive` 只是在该调用方断言成立、对应规则无错误、未知或结果截断时说明选定谓词域已遍历，不能升级为独立的完整性证明。空结果不能自动写为严格负缓存。应在不具备这些前提时使用已有严格 Snapshot 接口。

支持无显式 scope、无排序的受限 method_defs/class_defs 枚举及已实现的名称、签名、flags、调用和精确字符串谓词；不可转译的 QueryIR 会返回 `UNSUPPORTED`，不会静默忽略条件。调用边可选择随匹配方法返回，包含 DEX PC、引用域与 polymorphic 的额外 proto。不同 DEX、编码版本和复杂谓词仍须按能力检查及必要回退；041/036 等本入口不支持的版本返回 `UNSUPPORTED`，坏 magic、非数字版本及损坏标准头返回 `CORRUPT_INPUT`，并不表示已支持 041。

`Limits` 明确单 DEX 字节、总候选与调用数、输出 UTF-16 单元、每选中方法 code units/指令数及 JNI wire 上限。快速路径使用标准 C++ 分配，**不计入 Engine 账本**，以上限额不构成进程 RSS 上限；原 QueryIR `max_work` 在此模式不执行。调用同步，不能强制取消。单个 Java Plans 的扫描和关闭同步串行；可为并行 worker 分别创建计划，须由调用方限制并发与总资源。结果规则包含执行状态、未知数和结果截断标记，使用前必须检查；失败不能解释为空结果。

已有验证为有限 Windows JNI、固定真实 APK 与双 ARM 交叉构建/静态审核；尚未据此证明 Android/ART、完整 BIL 业务或性能目标。
