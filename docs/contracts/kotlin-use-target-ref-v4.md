# Kotlin v4 本地使用目标引用查询

`UseTargetReferenceQuery` 类型化构造一个 `target_ref` Join/SemiJoin，目标限定为 method_refs、field_refs 或 string_values，允许 use 或目标为左侧；只匹配同一 source occurrence 的本地目标编号，不按内容、符号或名称跨来源合并，也不解析运行时绑定。普通及 polymorphic 调用的 method_ref 可匹配，call_site 不匹配 method_ref。事件与实体谓词复用现有类型、UTF-16 编码和适用性校验；QueryID、Unknown、coverage 和结果由核心决定。

`TypedUseTargetReferenceExecution` 复用现有同步 v4 use-graph JNI，支持单源与多源快照；既有 JNI 限额及 incomplete 来源语义不变，显式 scope、Job 与更复杂图未由此构造器提供。标准库依旧由宿主提供；本接口不改变既有 Kotlin 类、C ABI 或默认查询。固定主机样本不证明 ART、设备、动态绑定或完整 QueryIR。
