# 静态 reflection flags 的关系查询 v14

显式同时声明 `required_capabilities:["reflection_flags_static","reflection_relational"]`，并在关系表达式中使用 `domain:"reflection"` 的 flags 或 owner_flags。新增位为 4194304，查询身份为 `query:v14:`、规范编码域 `DexMeguviz:QueryIR:reflection-relational-v14`。必须是关系表达式且含 reflection 谓词；旧 v13 的直接查询、旧 v3 图查询及各自 QueryID 不变，未声明新能力的 reflection 关系查询继续拒绝。

在 v13 静态 flags 模型基础上支持纯实体元数据的 scan/filter/label、union/distinct、group_by_owner、join/semi_join 及其既有作用域、排序和意图；不存在的定义、未解析类注解或未建模 flags 保持 Unknown。使用事实、numeric、继承、接口解析、use-stream、composite、unique-one 等能力组合明确拒绝，不把不可得事实当空集。常规排序字段 `flags` 仍是原始 DEX flags，不是反射投影。关系算子的多重集、身份、证据、预算和 Job 生命周期遵循 `relational-query-v3.md`；静态标志模型的边界遵循 `reflection-flags-v13.md`。

QueryID 按 v3 对象结构编码，但域和能力位不同；该标识不能替代来源快照。此为静态候选匹配，不证明 Java/ART 设备行为、ClassLoader绑定或全量关系能力。
