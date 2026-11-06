# BoundedExpand v5 功能合同（集中实现阶段）

在当前 v22 核心上移植已有 expand50 候选，实现单个 `bounded_expand` 及其外层关系组合。展开节点的输入、输出均为 `method_defs`，方向为 outgoing/incoming；普通 method-ref 调用按完整 owner/name/prototype 在声明来源范围内解析所有定义。保留每次来源出现、调用点 PC、候选定义分支、有序路径、未解析或未知前沿；不代表类加载、虚分派或实际运行。

`min_depth`/`max_depth`、`bounded_walk`、`paths`/`endpoints`、scope 交集、walk_where/emit_where 和 visited/edges/paths/work 预算沿用 ADR-0008 的既有设计。端点输出合并相同实体的路径证明，路径输出保留调用点与来源分支。incoming 在完整作用域内搜索调用者，不限于种子所在 DEX。无体方法产生零本地调用；特殊 invoke 不作为本 profile 的普通边。

QueryID 使用 `query:v5:` 和独立 `DexMeguviz:QueryIR:expand-v5` 域，能力位 8192。显式声明能力而不包含展开节点会拒绝。旧 v1–v22 的节点与版本域保留；本轮新增门控拒绝与 v6–v22 高位能力组合，尚未实现这些组合语义。

当前计划最多一个展开节点，输入与外层可使用既有关系表达式。已接通外层 filter、label、union、distinct、join、semi_join、group_by_owner，以及根 where 和显式集合语法。union 可把展开结果与其他普通关系合并；多个分支各含展开或嵌套展开仍明确拒绝。高位 profile 组合继续拒绝，不能称为完整 QueryIR/Q07。

最终主输出仍须是实体关系（0–6）；use 事件作为主输出需新的 tagged endpoint ABI，当前在编译阶段明确拒绝。已有低位 use 关系可作为连接证据出现，bindings/proofs 使用现有 tagged Value 保真；不因为 endpoint getter 的限制而丢弃其中的 use 域或 PC。方法体 using_strings/invokes/field_access 谓词继续可用。

外层算子保留每条路径的原始展开节点、seed、endpoint、来源、调用点和分组证明。join 合并两侧行证据，展开路径仍分组；semi_join 按左行身份输出并保留一个已证明匹配的右侧路径作为存在见证，不复制右侧多重性。按 entity distinct/set 合并同端点的所有路径证明后，后续行身份回到实体/绑定身份，不因证明路径数改变而重新拆分。owner 分组按成员实体计数；路径数量不是成员数，各成员的路径保留在类结果中。

未知前沿以独立的 opaque-unknown 状态沿外层传播，区别于调用方声明的 source scope 和已出现的 uncertain 行。半连接右侧没有可见匹配但仍有未知前沿时保留左行的未知可能；owner 分组不把未知前沿当作完整成员范围。前沿仍按原始展开节点记录，外层过滤不伪造一个尚未发现的 endpoint，也不据其过滤结果删除底层未知前沿；因此部分本可进一步证明的否定结果可能仍保守 Unknown。未解析且已完整搜索的静态引用仅表示声明范围内无定义，沿用原有前沿类型。

C ABI 新增 `dmg_expand_info`、路径、hop、前沿和 profile 的独立 getter，旧 struct 不改变；旧结果/Job getter 对不能表达路径的状态返回 Unsupported。CLI JSON 单独输出路径分组和前沿。另新增 `dmg_expand_row_evidence_info` 和五个 `dmg_result_get_expand_row_*` getter，分别返回行层的计数、bindings、links、proofs、witnesses；这些外层证据不塞入某条路径的 seed 证据。CLI candidate 同步增加 bindings、links、proof_bindings、witnesses。访问器适用于同步结果及 Job 的父 Result 批次视图，输出 size/索引失败不写出；文本与路径仍借用所属 Result。现有 struct 布局和旧入口的拒绝策略不变。Job 完成静态执行及物化后原子提交，再提供保留父结果的批次视图；取消、截止、分配或执行失败不提交成功半成品。集中物化函数也接入路径与前沿，供同步和多规则调用方使用。

本轮仅完成 Release 核心/CLI 编译，以及 outgoing/incoming/endpoint 三个连接性烟测，未运行完整 C ABI、取消/故障、旧域差分、ASan 或专项验收。移植了既有确定性样本及测试注册，留待统一验证；没有运行被过滤的 v5 模糊测试。Android/Kotlin 接线由其他工作流负责，本合同不构成设备/ART/BIL 或生产替换证据。

## 外层组合的集中实现验证范围

本批组合功能通过 Windows Release core/CLI 构建，以及五个连通烟测：filter+label+union+entity-distinct、local_owner join、owner group、semi_join、实体主输出与 invoke_sites RHS 的 tagged binding。样本核对行数、路径数、hop长度和外层证据可读性；另核对 use 主输出在编译时明确拒绝。没有运行完整旧域/独立字节 oracle、ABI错误参数/生命期、并发/取消/故障、ASan 或被过滤的 v5 模糊测试。统一专项验证仍待后续执行，本批不把 P1-08/P2-01 标为 done。
