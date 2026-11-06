# Kotlin method_defs 查询和值类型草稿

本切片生成有限 QueryIR JSON：method_defs 的 name、owner、prototype、return_type 文本匹配、参数数量和单个参数类型、raw DEX 方法/owner flags、方法种类、单个方法体字符串使用条件、all/any/not/常量和 enumerate/exists/unique。`parameterCount` 的数值与范围及 `parameter` 的索引均为 uint32；越界参数索引匹配 false。`usesString` 检查方法体中的 const-string 事实，不因字符串仅存在于池或注解中而匹配；多个条件可用布尔组合。方法种类为 DEX 静态声明语义，不提供运行时反射绑定。核心负责编译与规范 QueryID；`QueryExecution.execute(snapshot, query)` 接受单源或有序多源快照并通过有限 JNI method-v1 桥同步执行，结果不含独立见证、来源范围固定不完整。旧的无 snapshot 入口仍明确返回不支持；桥接上限和范围见 `jni-method-query-v1.md`。`QueryExecution.startMethodJob` 为单源及多源快照提供 `MethodQuery` 异步入口，直接复用 Java method-v1 Job 的范围、上限和暂定批次语义；读取至流结束后仍须检查终态，详见 `jni-job-method-v1.md`。`MethodQuery` 本身不构造完整参数列表或关系图，也不反序列化结果。

`EntityQuery` 和 `EntityPredicate` 生成 method_defs、class_defs、field_defs、method_refs、field_refs、type_refs、string_values 七种直接实体根的 JSON。支持适用根的文本、raw flags、owner flags、`has_local_definition`、方法签名/种类及 all/any/not；构造查询时检查所有布尔分支中的字段适用范围，不依赖短路。Unknown、来源 occurrence 及实际 QueryID 均由核心确定，不能从 JSON 构造成功推断结果完整。`EntityTextField` 只暴露固定字段枚举，复用方法查询的有界 UTF-16 编码与组合实现。

`ReflectionMethodUsesQuery` 和 `ReflectionMethodPredicate` 为限定 v15 的直接方法查询提供类型化构造，详见 `kotlin-reflection-method-uses-v15.md`；其专用执行入口与原始 JSON 入口共用 JNI 的范围和状态语义。

`QueryExecution.execute(snapshot, EntityQuery)` 通过 `queryEntities` 获取复制的直接实体结果，适用于单源或有序多源快照，来源范围仍固定不完整；具体可空属性和限制见 `jni-entity-query-v1.md`。若调用者手动将实体 JSON 传给旧 `queryMethods`，恰好属于 method-v1 的 `method_defs` 形状可以按原方法查询执行；非 method-v1 profile 会返回 Unsupported，不能当空结果。实体 Job 通过 `QueryExecution.startEntityJob` 提供有界 provisional 批次，具体生命周期见 `jni-entity-query-v1.md`。`GraphQueryExecution` 可转发 JSON 进行限定 v3 / v14 metadata 关系图查询或启动图 Job，返回核心静态见证副本；类型化元数据图构造及对应入口见 `kotlin-graph-dsl-v1.md`；独立见证验证仍是单独能力，JNI 图复制范围见 `jni-graph-query-v1.md`。

文本按 UTF-16 code unit 比较，保留 NUL、补充字符及未配对代理项。短查询优先保留原 `u16` 数组；当字节、节点或嵌套限制需要且替代表示可用时，使用 ASCII JSON `value` 字符串，逐单元转义，包括孤立代理项。两种编码经核心编译应具有相同 QueryID。前端按核心 JSON 结构预检深度，单片段、组合和最终文档均有 65,536 字节上限；组合按子项数及最终片段字节数作常数次线性扫描，并使用有界临时数组。该检查不约束调用方事先创建的 String、vararg 数组或已发生的分配，也不限制多次独立链式构造的累计成本。

组合会额外保留由各个更省字节且节点数不增的子项构成的候选，供整个查询外层容量不足时选择；它只替换在长度、节点和深度上均不劣的已有替代候选。混合选择不是穷举所有可行编码组合：若自动选择无法证明合适方案且原表示仍可输出，则保留原表示交由核心裁决；调用方可用 `textValue` 明确选择 JSON 字符串形式。若所有已尝试形式均超出片段大小或深度，则报告所选编码超限，不声称不存在其他理论表示。核心仍在编译时检查 16,384 个 JSON 节点、深度32及查询图复杂度；前端可序列化不代表核心必然接受。

`QuerySummary` 分别保存 execution status、coverage、decision 和 reason，不按行数推断存在或唯一；它是调用者提供的数据对象，不验证这些字段的组合是否来自真实结果。`SourceIdentity` 不验证调用者提供的字符串或运行时加载器绑定。当前 maxResults 限于 1–100,000，maxWork 限于正的 Kotlin Long 子集。

Kotlin 标准库目标版本为 2.4.21，由宿主提供；模块只用 compileOnly，不把标准库嵌入 AAR，也不作为生产 runtime 传递依赖。隔离构建在 Gradle 9.8.2 和 AGP 9.4.1 上验证。JVM 宿主类路径验证不代表 Android D8/R8、装载或设备执行已验证；JNI 的主机测试范围另见 `jni-method-query-v1.md`。






