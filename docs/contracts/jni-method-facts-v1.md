# Android 单方法事实读取 v1

`Snapshot.inspectMethodFacts(methodRef, requestedMask, maxRecords, maxWork, deadlineAfterMs)` 与 `SourceSetSnapshot.inspectMethodFacts(sourceIndex, methodRef, ...)` 接收同一snapshot中明确的DEX source index和method_ref，调用通用C ABI `dmg_snapshot_collect_method_facts_v1`，只对该本地方法执行一次checked decode。Kotlin使用 `MethodFactsRequest` 和 `MethodFactsExecution.inspect`；请求类别集合在构造时复制。此入口不改变旧 `inspectMethodCalls`、scope或持久缓存接口。

类别为 `STRINGS`、`FIELDS`、`NUMBERS`、`INVOKES`、`TYPES`、`INSTRUCTIONS`，可显式组合。`availability(category)` 分别返回 `NOT_REQUESTED`、`NO_BODY` 或 `CHECKED`；只有已请求类别可调用对应 count/item getter，未请求抛 `UnsupportedOperationException`，已检查的零项与无body通过availability区分。非本地定义的外部ref按native `Unsupported` 失败；非法参数、budget、deadline、损坏及关闭状态按原native错误传播，不交付部分结果。

结果按值复制caller descriptor和来源source/input/occurrence、snapshot、archive信息及六类静态事实；关闭snapshot后结果仍可读取。字符串与符号保留原始UTF-16码元，含NUL与孤立代理；字段含完整owner/name/type，调用保留普通/多态/custom域、target/ref/extraProto，类型使用点保留descriptor。数值 `bits` 是原始64位模式、`widthBits` 标识32/64、`kind` 区分常量与算术立即数；Java long为负不改变位模式，不推断浮点类型或运行时值。每个事实保留DEX code-unit PC与opcode；指令同时保留宽度及payload种类。

每次请求最多100000总记录、maxWork为1..100000000、deadline为0..86400000ms（0为不单独设截止）；超限不返回成功半成品。私有复制wire最多8MiB、文本总计最多1048576 UTF-16码元，累计事实最多100000；native Engine账本不含Java复制或线程内存。同步调用应由宿主安排到后台；deadline为协作检查而非硬实时终止。

当前固定Windows JVM/JNI样本、受控C核心及双ABI AAR静态审核已通过；真实Android/ART、完整错误交错、跨平台性能及DexKit全部语义尚需统一验收。输出是静态编码事实，不认证来源/loader，不等于可执行性、运行时调用、调用者逆向索引、完整DEX verifier或反射绑定。
