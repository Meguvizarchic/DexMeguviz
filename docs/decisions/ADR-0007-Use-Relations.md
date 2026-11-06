# ADR-0007 使用事实关系的身份与验收边界

状态：下一阶段设计；未知Relation的显式拒绝与事实夹具已实现，新的事实根、ABI和连接键尚未实现。

## 问题

当前 `collect_method` 可按需求产出完整的 StringUse、InvokeSite 和 FieldUse 向量，但谓词执行器只返回首个匹配见证。首个见证不是完整关系；一个方法在不同 PC 使用同一个目标时，两次事件不能合并。

## 身份与数据

事件身份固定为来源Occurrence、事件种类、caller MethodDef目录序号、DEX PC。每行另保留caller method_id、opcode、目标引用域和本地ID、code_item偏移；PC单位为16位code unit，指令字节位置从已检查的 `code_offset+16+2*pc` 推导。不得仅以调用者、目标名称或内容hash作为身份。

InvokeSite的普通method引用、polymorphic的method引用及额外proto、custom的call_site引用必须分域。当前目录只有call_site数量，未解析bootstrap；不能将其当普通callee，也不能宣称运行时解析。字段读写按实际opcode分类。

## 扫描与证明

按选定来源内的MethodDef遍历，逐方法使用既有checked collector。必须完成当前方法的整段指令和异常边界验证后再发布事实；前面出现匹配、后面损坏时不得伪装为Complete。无body是已知无指令；未请求、未分析、取消、预算耗尽、损坏与Unsupported均为不同状态，不能统一为空集合。

每次collector的结果与指令向量受scratch预算约束，事实记录必须按值复制到可保活的查询结果／目录，不能保存临时vector指针。中间行、结果和证据分别计账；根输出上限不能提前截断待完成的方法或连接。

事实Scan预先知道的是待检查方法数，而非事件数。profile应显式报告方法总数、已访问、无body、已解码、事件数和code units，并注明计数域；混合Scan不能把方法数与事件数相加后叫作事件总数。正见证可单方法局部复核；不存在或Unique为真仍需完整相关范围。

## 类型连接与ABI

同源caller连接使用source+caller ordinal；同源target_ref连接按引用域连接StringValue、FieldRef、普通／多态MethodRef，不允许裸索引跨DEX匹配。跨来源的定义解析另用完整SymbolKey并保留所有匹配，不代表ART分派。暂未实现的call_site bootstrap连接必须显式Unsupported。

当前 `dmg_entity_row`、binding和relation link只有local_index，不能无损表达PC。使用事实必须增加独立、带out_size的typed结果和tagged binding／proof／link getter；旧getter对无法无损表示的事实条目返回Unsupported。原有结构、关系枚举值、v1/v2/v3 QueryID和既有计数解释保持兼容。Result/Batch需保活事件值、标签、来源与证明。

`reference::relation_size`、`entity`及执行器入口已对未知关系类型返回Unsupported，包括空来源和空范围；不会把未接通的根报告为Complete空集。类型编译、扫描、物化和公开接口必须同时接通后才启用对应能力。

## 首批验收

- `method-uses.dex` 的uses为MethodDef ordinal 2／method_id 3：StringUse PC0/string_id10、InvokeSite PC2/method_ref4、FieldUse PC5/field_ref0；仅在pool中的字符串不算使用。
- `invoke-domains-038.dex` 包含PC0 polymorphic/method_ref4/extra_proto0及PC4 custom/call_site0；只证明结构域，不证明bootstrap或ART。
- 新建可重建的原始DEX：同一caller在两个PC调用同一目标；同字段读/写；普通和jumbo字符串；相同字节两个来源；前面命中后续坏opcode；预算／取消／分配失败。
- 验证caller与target同源连接、不同DEX相同局部索引不误连、跨来源完整符号多定义不丢失、Unique零／一／多与Partial、Result/Batch在释放原句柄后的PC及证据保活。
- 使用独立原始字节oracle核对PC与引用域；设备加载、ClassLoader和Hook另行验收。
