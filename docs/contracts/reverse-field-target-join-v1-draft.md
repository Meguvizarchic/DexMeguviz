# 显式字段反向 target_ref 连接（内部实验）

`dmg_query_execute_reverse_field_target_v1` 是单独的同步实验 C 入口，接受仅 v4 的直接 `join(target_ref, scan(field_uses), scan(field_refs))`；方法反向入口 `dmg_query_execute_reverse_target_v1` 仍拒绝该形状。其他方向、Filter/Union等嵌套形状、混合高级能力、Job 和批量 opt-in 均不支持，不静默回退。旧单次和 Job/批量不自动使用索引。

索引由 snapshot 所属 Dataset 提供，按同一 source occurrence 的 field_ref 编号查找；对已经选出的 checked 前向事件及已选目标引用的交集逐项比对：应有的匹配缺失、匹配字段不符或重复时拒绝；页面中不属于所选前向事件的记录会被跳过，不会逐条验证这些未选记录或整个索引。该入口仍依赖反向索引对所请求来源和目标的正确性，不是索引完整性或对抗篡改证明。结果按原左/右顺序物化，保留原 QueryID、读写 opcode、PC、来源、绑定、见证、Unknown 与 scope；不同来源相同编号不能匹配。扫描空输入不请求索引；索引只证明静态引用，不证明运行时字段绑定、跨来源符号等价或 ART。

使用已有 `dmg_reverse_join_options_v1` 精确尺寸和限制，额外索引/适配工作受独立限额；错误 out 为 NULL，完整索引可能在后续物化失败时保留。结果与独立查询须逐字段对照，但索引和结果同时驻留及新增工作可能改变内存峰值、预算失败阈值与错误/取消时机，不承诺全部阈值等价或性能收益。有效输入须遵守已有 snapshot/engine 生命周期和不重叠输出契约；关闭后拒绝入场，同步入口无外部取消回调。

本实验不改变稳定 ABI 布局、不启用 JNI/CLI/BIL，不代表完整P1-07/P1-08/P2-01、全关系IR、设备或运行时验收。

独立字符串实验入口与本入口分开，见 [字符串反向连接合同](reverse-string-target-join-v1-draft.md)。
