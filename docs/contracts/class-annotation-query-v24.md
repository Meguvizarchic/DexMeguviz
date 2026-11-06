# 静态类注解查询 v24（受限候选）

直接 `class_defs` 的 `where.annotation` 精确匹配本来源的注解类型，可选指定 visibility 及一个顶层 `VALUE_INT` 元素；必须显式声明 `required_capabilities:["class_annotation_static"]`，QueryID 独立为 `query:v24:`。例如：

```json
{"schema_version":1,"relation":"class_defs","where":{"annotation":{"type":"Lfixture/Complex;","visibility":1,"element":{"name":"n","int":-7}}},"required_capabilities":["class_annotation_static"]}
```

`type` 和 `element.name` 是严格 UTF-16 等值字符串，按既有 DEX 035–040 名称规则并集验证（包括 040 扩展空格），明确非法名称拒绝，`visibility` 为可选的 DEX 数值 0/1/2，`int` 必须是有符号 32 位整数，编码宽度按 DEX 符号扩展。指定类型不存在、visibility 不同或显式元素种类/数值不等时为 No；注解存在但指定元素未编码时为 Unknown，因可能有默认值，`not` 不反转 Unknown。该保守语义与 DexKit 对缺失显式元素的匹配不等同，未声称真实 DexKit 差分或兼容。类型、元素属于同一个注解及同一 DEX occurrence；输出仍是类定义，重复来源不合并。

当前仅支持直接 class_defs、既有来源 slot scope、元数据、布尔组合、enumerate/exists/unique；不支持排序、top-n、关系图、opcode 或 v20 等高级 profile 混合、方法/字段/参数注解、嵌套/数组或默认值解析。未实现组合明确拒绝。035–040 支持；041 拒绝。扫描/嵌套读取与文本比较计入现有 max_work，取消和 deadline 沿用 Job；资源/损坏错误不变成零匹配。没有单独的注解位置 witness，不能借此声称逐元素证明。metadata reader 与实际加载器真实性和 ART 验证仍是不同边界。

C ABI 原 `dmg_query_info` 的 32 位 required_capabilities 掩码已满，结构保持不变；v24 的旧查询/结果信息和旧 explain 接口返回 Unsupported、不写输出，防止位图被误认为完整能力。使用带精确 size 的 `dmg_query_get_info_v2`、`dmg_result_get_query_info_v2`、`dmg_job_get_query_info_v2`：`legacy` 包含旧位图及 `query:v24:`，`extended_capabilities` 明确给出 `class_annotation_static`；字符串借用对应句柄。旧 profile 的旧 getter 行为不变，v2 的扩展字符串为空；非终态 Job 也可读取不可变计划身份，Job 状态和结果成功需照常分别检查。旧 Android 桥保持拒绝；独立 `ClassAnnotationQuery` 同步入口支持单来源及 SourceSet 全输入，继续拒绝显式 scope；独立 `ScopedClassAnnotationQuery` 同步入口支持显式输入槽范围；全输入 `ClassAnnotationQuery.startJob` 提供 EntityJob，显式 scope 的独立 Job 可通过 `ScopedClassAnnotationQuery.start` 使用；尚无 ART 验证。通用 CLI 查询使用 v2 输出 v24 profile 和扩展能力；旧 explain 接口明确返回 Unsupported。

Windows 主机 C ABI 固定夹具通过，覆盖负数、三值、来源、预算、背压取消与拒绝；内部合成篡改控制检测坏编码。三条旧 profile QueryID 对照保持一致；不是完整 ABI、设备、兼容或性能验收。

优化候选：同一次执行中，每个来源的 evaluator 按需缓存已检查的注解区段表；首次读取与失败路径保持原有行为，后续使用前逐单位重放相同逻辑 work 与取消检查。缓存不跨来源或执行，不减少逻辑预算；要求来源字节保持已有不可变合同。该优化的实际速度和设备行为未验。
