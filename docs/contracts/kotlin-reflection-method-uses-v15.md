# Kotlin 类型化 v15 方法查询

`ReflectionMethodPredicate` 可组合原有 `MethodPredicate`、反射 flags、字符串使用、调用目标和字段读写条件，支持 all/any/not。`StaticTextMatch` 沿用既有 UTF-16 码元编码，包括 NUL 和孤立代理项；调用与字段条件检查的是静态引用，不推断运行时分派。调用参数范围是 uint32，call-site 不支持声明方法符号条件。每个 use 量词需要 1–128 项，布尔组合每层最多 128 项。

`ReflectionMethodUsesQuery` 要求构造器中显式出现反射条件与至少一个通过 v15 类型化 use 构造器创建的条件，并声明 `reflection_flags_static` 和 `reflection_method_uses`。它限制最终 ASCII JSON 不超过 65,536 字节，结果数最多 4,096、工作量最多 100,000,000，使用原有 MethodPredicate 片段不自动推断其内部是否含 use。核心仍负责检查完整 JSON 节点和深度、编译、能力及三值逻辑；前端能生成 JSON 不保证核心接受。

`TypedReflectionMethodUsesExecution` 提供单源和多源的同步及 Job 入口，委托专用 v15 JNI 桥，来源固定 incomplete；批次仅 provisional，须读到 EOS 后检查终态。结果不含方法体见证，也不代表 ClassLoader 绑定或 ART 反射行为。Windows JVM 固定样本与 CLI 对照的证据不代表 Android/ART、所有组合或错误路径均已验证；Kotlin 标准库由宿主提供。
