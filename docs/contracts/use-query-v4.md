# 使用事实查询 v4

本契约描述 `dex-query-use-v4` 的当前实现，不构成完整验收结论。基础实体、算子、作用域、三值逻辑和结果意图沿用 `relational-query-v3.md`；内部扫描边界见 `use-scan-v1.md`。契约与代码冲突时应先核验并修正，不能把样例通过推断为完整 DEX verifier 或 Android 运行支持。

## 事实、身份与输入

JSON 使用 `schema_version: 1`，三个事实关系须使用对象 `scan`：`string_uses`、`invoke_sites`、`field_uses`；字符串关系入口不接受这些关系。包含任一事实 scan 的计划标为 `dex-query-use-v4`，QueryID 使用 `query:v4:` 和 `DexMeguviz:QueryIR:use-v4` 域；不含事实的既有 v1/v2/v3 编码应保持兼容。能力发现字符串包含 `dex-query-use-v4` 标识；以实际 C 消费者验证为准。

每个事实身份是 `(source_index, relation, caller_ordinal, dex_pc)`；`caller_ordinal` 是该来源方法定义目录中的本地序号，`dex_pc` 以 DEX code unit 计。同一方法对同一目标在不同 PC 的两次引用是不同事实；相同内容的不同来源 occurrence 也不能合并。事实还保留 caller method_ref、code_offset、opcode、target_domain、target_index 和 extra_proto。entity 去重采用完整事实身份；tuple 去重另包含规范化角色绑定和左右路径，见 v3 契约。输入 DEX 与 Facts 同源、快照来源身份和执行范围并不证明设备上的运行时绑定。

| 事实关系 | target_domain | target_index | extra_proto |
|---|---|---|---|
| string_uses | string_value | string ID | UINT32_MAX |
| field_uses | field_ref | field ID | UINT32_MAX |
| invoke_sites | method_ref | method ID | UINT32_MAX |
| invoke_sites | method_and_proto | method ID | proto ID |
| invoke_sites | call_site | call_site ID | UINT32_MAX |

多态调用保留额外 proto；custom 引用的 call_site 索引须在范围内；输入读取另检查数组起点、前三值、方法句柄类型和引用范围。当前不解析 bootstrap 方法签名，也不把 call_site ID 当 method ID；这些结构检查不表示 ART 可装载。

## 谓词、连接与结果

事实行谓词支持 `all`、`any`、`not`、`caller_name`、`caller_owner`、`pc`、`opcode`、`target_index`、`target_domain`；数值可为精确值或 `{"min": ..., "max": ...}`，文本匹配沿用现有规则。事实行可按 caller 的 `owner`、`name`、`prototype`，以及 `source_index`、`local_index`、`pc`、`opcode`、`target_index` 排序。未实现的属性、排序或类型组合须明确拒绝，不应返回看似完整的空结果。

事实参与同类型 `scan`、`filter`、`union`、`distinct`、`label`、`same_entity` 连接，以及下列额外 Join/SemiJoin 键。输出主行类型继承左侧，连接保留左右路径和证据；`group_by_owner` 输入仍限成员定义，不直接按事件分组。

- `caller`：`method_defs` 与任一事实关系，双向可用；必须同来源且方法定义序号等于事件 caller ordinal。
- `target_ref`：`string_uses` 与 `string_values`、`field_uses` 与 `field_refs`、`invoke_sites` 与 `method_refs`，双向可用；同来源且目标 ID 匹配。普通与 polymorphic 的 method ID 可连 method_refs；custom 不匹配 method_refs。
- `same_entity` 对相同事实关系比较完整来源、关系、caller 和 PC。事实不支持通过 `symbol`、`local_definition` 或 `local_owner` 直接跨来源连接。

例如 `{"schema_version":1,"relation":{"op":"scan","relation":"invoke_sites","where":{"target_domain":"method_ref"}},"intent":"enumerate"}`。扫描每个方法时先检查其完整指令范围，再暂存事实；损坏、预算、取消或分配失败不会作为成功的部分 Result 返回。该 checked 子集并非完整 DEX 验证。

## 覆盖、范围与计数

显式作用域与来源不完整遵循 v3：缺少显式 slot 返回 SourceMismatch；未声明完整范围的无匹配不能证明不存在。SemiJoin 右侧范围不完整且无确认匹配时保留 Unknown；GroupByOwner 对缺失来源可能改变成员数量或角色的组保守标为 Unknown。coverage 与 decision 分开：可靠存在证据可以证明 Exists，而无可靠证据且范围或属性未知时为 Undetermined。结果截断不能证明唯一。

事实 scan 的 total/visited 以方法定义为单位，另报告 attempted、no_body、decoded、events_collected、code_units；普通实体 scan 以实体记录为单位。v2 状态将 `entity_visited/entity_total`、`method_visited/method_total` 和 `events_collected` 分域；operator profile 的 `scan_domain` 标记该算子使用的单位。重复 scan 分支可重复计数；这些量不是去重实体数，不能相加后称为方法数。失败中的统计只作局部诊断，不能当成完整范围或部分成功结果。

## C ABI 与生命周期

草稿新增按精确输出大小检查的 v2 value、binding、proof binding、link、relation witness、relation info 和算子 profile getter，Job 提供相应 v2 关系状态、等待及 profile。tagged value 分 entity/use；事件端点保留 PC，普通实体端点的 PC 为 UINT32_MAX。binding/proof path 通过已有路径 getter 读取。文本和路径为 Result/Batch 的借用视图，承诺在对应结果最后释放之前有效；该承诺及 Engine 原句柄释放后的事件 Batch、证明和错误尺寸行为已由隔离 C 消费者与 ASan 测试覆盖，但不代表所有消费者或设备场景通过。

计划包含事实 scan 时，旧 relation info、旧关系 Job status/wait 和旧 operator profile 返回 Unsupported，避免把实体与方法计数混称；旧 entity、binding、proof binding、link、relation witness 不能表达具体事件身份时返回 Unsupported。旧方法 Result/Batch/Job 状态接口对对象关系查询也保持 Unsupported。其他仍能表达的信息接口按各自契约使用。Job EOF 不是成功证明，须检查最终 v2 状态。

## 验证与未完成范围

已有隔离样例与独立 oracle 覆盖六份固定 DEX 的部分事件、来源与连接；这不证明所有 QueryIR 组合、ART、bootstrap、JNI/AAR、设备执行或性能。事件证明、保活和尺寸边界已由隔离主机测试覆盖；主机回归、有限 fuzz 与两个 Android ABI 编译证据见 `docs/evidence/iteration11.md`。BoundedExpand、完整关系 IR、完整 DEX verifier、运行时绑定及 BIL 兼容均不由本草案声称完成。
