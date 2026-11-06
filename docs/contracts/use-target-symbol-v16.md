# 使用事实目标符号连接 v16

本 profile 新增 `Join` / `SemiJoin` 的 `on: "target_symbol"`，计划必须显式包含 `required_capabilities: ["use_target_symbol"]`；能力位为 16777216，QueryID 域为 `DexMeguviz:QueryIR:use-target-symbol-v16`，前缀 `query:v16:`。旧计划的能力位、规范编码及身份不变。没有对应连接却声明此能力、或使用连接却不声明能力，均返回 Unsupported；继承、数值、接口、use-streaming、composite、unique-one 与 reflection profile 的组合暂不支持。

三类事实事件均可作为任一侧，另一侧分别为：`invoke_sites` 与 `method_defs`/`method_refs`、`field_uses` 与 `field_defs`/`field_refs`、`string_uses` 与 `string_values`。方法匹配完整 UTF-16 owner、名称、prototype；字段匹配 owner、名称、类型；字符串按完整 UTF-16 值比较。先从事件所属来源和目标 ID 读取引用，再与另一来源的实体值比较；这不会将两个 occurrence 归并。Join 保留每个调用点与每个静态匹配实体，SemiJoin 保留左行重数和一个证据，右侧重复不放大结果。目标作用域有多份匹配定义时保留全部 Join 配对，不推断运行时选择；右侧不完整且无命中时 SemiJoin 保持 Unknown。

`invoke-polymorphic` 的 method_and_proto 保留额外 proto，它与 method_ref 的静态符号进行连接，不表示运行时方法分派或把 extra proto 当作引用声明 prototype。`invoke-custom` 的 call_site 不与 method_ref/definition 连接。调用点 PC、引用域及左右 binding/link 由现有 v2 值与证明接口表达；新 link key 数值为 `DMG_JOIN_TARGET_SYMBOL=6`，不改变既有键。资源、范围、三值决策和失败提交沿用现有 v4 关系合同。

此 profile 不代表完整 QueryIR、DEX verifier、运行时绑定、Android/ART 或 BIL 验收。固定样本不能替代全部来源组合、错误注入、取消、异步 Job 生命周期及独立跨使用方验证。
