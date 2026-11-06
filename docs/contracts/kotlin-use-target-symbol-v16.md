# Kotlin v16 使用目标符号查询

`UseTargetSymbolQuery` 为一次 `target_symbol` Join/SemiJoin 提供类型化构造：可选择方法定义、方法引用、字段定义、字段引用或字符串值，以及使用事件或目标实体作为左侧。`UseEventPredicate` 支持 caller 名称/owner、PC/opcode/目标索引、目标域和布尔组合；目标实体条件沿用 `EntityPredicate`。类型不适用、无效 uint32 区间和超出 JSON 上限的输入显式拒绝。文本保留 UTF-16 码元，包括 NUL 和孤立代理项；QueryID 与求值由核心决定。

`TypedUseTargetSymbolExecution` 支持单来源及多来源快照的同步执行，自动声明 `use_target_symbol` 并使用现有 use-graph JNI。来源范围仍不完整，不将静态符号匹配解释为 ClassLoader 选择、虚调用分派或设备行为。Kotlin 标准库由宿主提供。此类型只表达一个 v16 符号连接；更复杂的图、排序、显式 scope、Job 和其他能力组合仍须使用相应现有接口，原生编译及 JNI 限额仍是权威。
