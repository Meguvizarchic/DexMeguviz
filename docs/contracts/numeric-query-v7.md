# 数值位模式查询 v7

本profile只描述被检查的 DEX 指令字面量，不能推断运行时类型、浮点语义、执行结果、可达性、数组载荷或静态初值。

对 `method_defs` 使用 `{"numeric_bits":{"width":32,"bits":"ffffffff","kind":"constant"}}`；`width` 必须为32或64，`bits` 恰为8或16位十六进制字符串，大小写等价；`kind` 为 `constant`、`arithmetic_operand`、`either`。按完整位模式、宽度、种类判定一个方法是否包含至少一个事件。不同宽度永不相等；输入不做浮点转换、截断或符号解释。无body方法无此事件，返回有界的 no-body 反证；异常、损坏、预算和取消不得转为空集。

需求位8触发一次 checked walk 数值采集，尚未请求时不触碰方法指令；按每事件比较计工作量。布尔组合、作用域及来源一致性沿用既有三值执行约定。方法定义的直接查询和关系表达式上的方法谓词均适用；其他根拒绝数值条件。显式 `required_capabilities:["numeric_literals"]` 采用 v7 身份域，required-capability 位为 32768；数值见证 kind 为9。新 query ID 为 `query:v7:`，规范编码域为 `DexMeguviz:QueryIR:numeric-v7`；旧 v1–v4 查询编码和身份保持原有分支。与 v6、v8 或 v9 混用时遵循 [v10 组合契约](composite-query-v10.md)；v5 尚未开放。

正例使用 `dmg_result_get_numeric_witness_v1`，保留来源、方法定义序号、运算节点、PC、opcode、32/64位宽、literal kind、uint64位模式和完整被检查方法的code units。旧 witness getter 遇到 numeric 证据返回 Unsupported，不能截断；新 getter 对其他证据返回 Unsupported，输出尺寸不符时返回 InvalidArgument。数值 witness 随 Result/Batch 保活。CLI 用定长十六进制字符串输出全部位模式。

需统一验收：同步/Job、关系深层绑定、相同方法引用与定义序号不同、无 body、短路、全部常量及算术编码、错位宽/来源/PC/值的独立字节反例、失败与预算、v1–v4 ID和 ABI 差分、ASan及两 ABI 交叉构建。原生测试不证明 ART 或完整 DEX verifier。
