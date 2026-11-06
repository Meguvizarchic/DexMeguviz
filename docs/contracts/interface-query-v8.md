# 静态接口字段查询 v8

`declares_fields` 的 `scope: inherited_interfaces` 统计静态 superclass 与直接/间接 superinterface 的**联合继承成员**，并非只统计接口声明。当前实现是来源限定的静态候选模型，不是 Java 反射、ClassLoader 解析、ART 类型验证或运行时字段绑定。查询使用 `query:v8`、`dex-query-interface-v8`、required-capability 位 65536、谓词节点编号31和见证 kind10；显式 `required_capabilities:["interface_fields"]` 即使没有该谓词也进入 v8 身份域。与 v7 或 v9 混用时遵循 [v10 组合契约](composite-query-v10.md)；与 v6 混用仍为 Unsupported，v5 尚未开放。

每个 superclass 候选路径单独求值；类型边按当前谓词的有效来源范围解析完整 UTF-16 descriptor，同字节不同 occurrence 不合并。接口类型如果缺定义、有多个匹配定义、指向非 interface、来源不完整或图有环，相关分支保守 Unknown；interface 自身作为查询根也暂保守 Unknown。接口类型目前只给 raw public+abstract+interface 且最多包含 synthetic/annotation 附加位的形式确定结果；例如正常 public annotation interface 支持，包可见或其他形式保守 Unknown，不等同宣称其非法。包可见和矛盾访问位不推断 runtime package。接口字段只识别 raw public+static+final，允许额外 synthetic；其他接口字段标志形成 Unknown，并不宣称输入一定不能被任何运行时接受。

对于完整、唯一解析且无异常访问位的有向无环静态图，节点的自身字段按名称隐藏其父类型中同名字段；父类型成员按来源 occurrence 与字段 definition ordinal 去重，因此菱形路径到同一声明只计一次，不同接口/类的同名不同声明仍分别计数。只统计根的继承成员，根自身字段只参与遮蔽。字段类型、raw flags 与文本条件在实际声明源匹配。不同 superclass 分支只有一致的 Yes 或一致的 No 才得出确定结果；否则 Unknown。最小0／最大UINT32_MAX是恒真计数条件，其它不完整场景不据部分计数推断。

范围按 inherited-v6 的关系规则选择：Scan 使用顶层与自身 scope 交集，Filter 使用其输入子树 Scan 来源并集；仅首次实际求值且 owner 已知时准备。节点、边、成员和证据使用 scratch PMR，各次枚举、比较及路径工作计入 max_work，max_intermediate_rows 约束各中间容器及见证数量。取消、预算或内存失败不返回伪造完整空结果；Job 批次仍为 provisional，终态另查。

## 见证

`dmg_result_get_interface_witness_v1` 使用准确输出尺寸并保留 Result/Batch 来源生命周期；旧 getter 对 kind10 返回 Unsupported。`operator_node` 为关系算子 stable ID，直接查询为 UINT32_MAX；`branch_index`、`node_index` 是同一叶谓词、同一 superclass 分支中的局部编号。每个条目的 `source_index/relation/local_index` 共同定位原始实体或类型引用：

- item0：owner 不可用；item1：类型节点（`detail=1` 表示 interface，0 表示 class）；item2：边（`node_index` 是来源节点、`aux` 是目标节点，`detail=0` superclass、1 superinterface，实体定位来源 DEX 的 type_ref）。
- item3：frontier（`detail` 1 missing、2 ambiguous、3 非接口定义、4 incomplete、5 cycle、6 access unknown、7 不支持的 interface 字段、8 不支持的 interface 类型标志、9 interface 根暂不支持、10 superclass 路径含 interface；`aux` 为具体候选数量或字段序号）；item4：匹配的真实 field definition；item5：分支结果（`aux` 为匹配数，`detail` 的最低位表示不完整，其余位为内部 Yes/No/Unknown）。

图与字段见证必须连同匹配谓词、来源范围和原始 DEX 独立核对；SHA-256 身份或校验和不证明运行时继承。静态参考可查 [DEX 格式](https://source.android.com/docs/core/runtime/dex-format)、[JLS 8.3](https://docs.oracle.com/javase/specs/jls/se21/html/jls-8.html#jls-8.3) 和 [JLS 9.3](https://docs.oracle.com/javase/specs/jls/se21/html/jls-9.html#jls-9.3)，但本能力针对 DEX 静态候选，不把源语言约束自动套用为 ART 结论。
