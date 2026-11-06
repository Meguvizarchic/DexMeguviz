# BoundedExpand / Q07 首版实施设计

本文是设计稿，不代表功能已实现。工程范围来自 `<LOCAL_PATH> 第 5 点、`DexMeguviz_Engineering_Plan.md` 6.2/12.3 的 BoundedExpand、Q07/Q09–Q12 和现有 `docs/contracts/use-query-v4.md`。它仅描述静态事实候选，不证明 ClassLoader 解析、虚调用分派、ART 或真实运行。附件提供工程需求，不提供设备/BIL操作授权。

## 1. 输出与查询契约

新增关系算子 `bounded_expand`，`input` 必须是 `method_defs` 关系，主输出也是 `method_defs`（端点）。输入 seed 的 source occurrence、主实体、角色绑定与已有证明均保留；端点使用自身实际来源，跨 DEX 时可以不同于 seed，不能把相同 DEX 字节的不同 occurrence 合并。建议明确参数如下（字段名和数值属于待实现的 v5 合同，不预称现有 CLI 已接受）：

```json
{"op":"bounded_expand",
 "input":{"op":"scan","relation":"method_defs","where":{"name":"A"}},
 "edge":"invoke_method_ref", "direction":"outgoing", "resolution":"all_definitions",
 "scope":{"slots":["base","split1","split2"]},
 "max_depth":2, "min_depth":1, "cycle":"bounded_walk", "output":"paths"}
```

- 支持方向 `outgoing` 和 `incoming`；边是受 checked 指令解码的普通 invoke，目标域必须是 `method_ref`。明确排除 `method_and_proto` 的 polymorphic 与 `call_site` 的 custom；请求它们或把笼统 `all_invokes` 当成本 profile 的边时返回 Unsupported。ordinary invoke-virtual/interface/super/direct/static 仅表示对 method_ref 的静态引用，不等于实际运行的实现。
- `scope` 是**调用事件所属来源及所有候选定义解析的封闭搜索域**，与顶层 scope 取交集；两者均未显式指定时由 Dataset 的声明完整性决定。非空未知 slot 报 SourceMismatch；显式空集合是完整的空域。每个输入 seed 亦必须处于该域；域外 seed 不属于结果。不得通过 ContentId 合并 occurrence。此定义同时适用于 incoming，防止先以 seed 作为解析域导致遗漏其他同符号定义。
- 首版明确 `resolution: all_definitions`：按完整的 UTF-16 `(owner descriptor, member name, prototype)` 在作用域内收集所有匹配的 `MethodDef`，不得只选首项；多于一项时每条解析边标记候选数与 `ambiguous=true`，每个候选分别扩展。没有定义时记录 unresolved frontier 及完整 `MethodRef`；若相关域完整则表示**该声明域内无定义**，不是运行时不存在；域不完整时为 Unknown。其他解析策略返回 Unsupported，不得把未实现的策略改为空结果。
- `cycle: bounded_walk` 表示允许同一实体或边重复经过；每路径严格至多 `max_depth` 跳，故 `A→B→A` 的第二跳是合法路径，继续至上限即可，不使用全局 visited 消掉重复路径。允许 `max_depth=0` 和 `0≤min_depth≤max_depth`。depth 0 是 seed 本身的零跳路径；`min_depth=0` 才输出 seed。无递归调用栈，计数及深度加法检查溢出；不把现有 `Binding.path[32]` 的二叉表达式路径上限错误当作调用链深度上限。资源上限另行约束遍历。
- `output: paths` 是有序调用点路径的 bag：每个输入 bag 行、每个 source+caller+PC 的 invoke、每个解析定义分支分别生成路径；双 PC 不合并。路径身份为 seed 的 occurrence/完整绑定 + 顺序 hop 的调用点和解析目标 occurrence；完全相同路径由重复输入产生时 bag 多重度保留，`Unique` 的路径身份仍应按完整路径去重。`output: endpoints` 按完整端点 EntityKey 集合去重，汇总所有已发现路径证明；同符号不同 occurrence 是不同端点，不按 descriptor 去重。禁止把一个端点的多个路径简单 flatten 成无分组 links。
- 方向是遍历方向；每 hop 的物理事实始终记录调用者、PC、目标 method_ref 和所选定义。incoming 以目标定义为起点反向查找**所有作用域内调用者**，检查其普通 InvokeSite 的完整符号经 `all_definitions` 能解析到当前定义，然后生成 caller 端点；必须搜索整个边来源域，不能仅搜索当前 DEX。
- 可选 `walk_where` 和 `emit_where` 应分别编译为方法定义 typed 谓词。`walk_where` 判断当前节点是否可继续向下一层扩展；`emit_where` 仅决定在合法深度是否输出，不得阻止继续遍历。seed 默认允许开始遍历；在其他节点，对 `walk_where=false` 可以输出该节点但不继续，Unknown 分支必须保守保留未知可能性。为避免无意缩小验收，若首版暂不实现这两项，应对带此参数的计划明确 Unsupported，并在能力/文档写明，不能忽略字段。
- scope、方向、边域、解析策略、min/max 深度、循环策略、输出身份、两类过滤与资源限额均为语义显式值或确定默认值。Root 的 `max_results` 在遍历、残余过滤、去重/身份判断后生效；TopN 必须先完成声明范围再全局排序。

## 2. 多定义、未知与结果意图

用 `RefKey=(caller occurrence, MethodRef local index)` 提取原始 UTF-16 符号；同一输入的 local index 不能跨 DEX 使用。按完整键逐个比较，哈希仅预筛；同源有定义不排除其他来源同符号定义。将定义集合与选择器的 completeness 一并返回。

`all_definitions` 的每个候选属于被声明的**静态候选关系**。当范围不完整时，即使发现已有定义，其他未发现定义仍可能增加分支：对已发现路径可以保留有效正见证，但要记录潜在 unresolved/ambiguous frontier 与 Partial coverage；不能把现有候选数标成完整唯一解析。未知的输入谓词、walk/emit 谓词继承三值逻辑：false 可排除，unknown 不可当 false；NOT unknown 仍 unknown。无法表达未知端点为真实 MethodDef 时，将其作为明确的 frontier 诊断/unknown 计数保留，而非伪造实体或成功空表。

| 情形 | 决策与覆盖 |
|---|---|
| 有已确认路径且问 Exists | ProvenTrue 可成立；若范围/路径未完，coverage 仍 Partial |
| 完整范围且无确认/未知路径 | Exists 为 ProvenFalse/NoMatch；Unique 为 ProvenFalse/NoMatch |
| 无确认路径但有 Unknown 或范围不完整 | Undetermined，不得 NoMatch |
| Unique 一种身份且可能还有未知 | Undetermined；`max_results=1` 不能证明唯一 |
| Unique 至少两种确认身份 | ProvenFalse/Ambiguous 可成立；覆盖仍独立报告 |
| 两条不同 PC 指向同端点 | endpoint Unique 可为 1；path Unique 为 2，除非声明不同 identity |
| 显式封闭 scope 内引用无定义 | 记录 unresolved（scope内零匹配），不将其宣称为运行时未解析；不构造到外部目标的定义 |

凡内存、访问、边或路径预算耗尽，本首版**整个执行返回 BudgetExceeded，不提交成功的部分 Result/Batch**；Job 可读已记录的 profile 与终态错误但 EOF 不代表成功。取消、deadline、corrupt opcode、Unsupported 和 OOM 分别保留错误，不转换为零匹配。可供未来增加有明确定义的 Partial 发布协议，但不得在目前 atomic 合同下悄悄发布部分路径。

## 3. 执行与资源

以 `(seed row, current MethodDef, depth, ordered hops, uncertainty)` 为迭代工作项，深度优先或广度优先仅为物理选择；可观察顺序需明确为 seed 输入顺序、调用点 PC、候选 `source_index/local_index` 的稳定顺序（incoming 以 caller identity、PC、resolved identity 为 tie）。对所有输出形状只在语义过滤及 endpoint/path 身份处理后应用结果上限。先按需调用 checked method facts/decoder，完整检查当前方法；无 body 是真实的零本地 invoke，不代表运行时无动态行为。

Incoming 可按需构造 `MethodRefSymbol→InvokeSite` 反向索引，或标量遍历全部作用域方法；未请求 incoming 不构造 reverse index，并显式统计 build/reuse 次数。来源/元数据、引用、定义均分开；如果索引使用 hash，碰撞后必须完整键比较。重复 scan、不同 seed 或不同路径的缓存只复用经过相同 snapshot、scope、边域和解析策略验证的工作，不能复用失败半成品。多定义候选不可在一个 DEX 内优先匹配后直接短路。

按请求声明并记账 `max_work`、`max_visited`、`max_edges`、`max_paths`、现有 `max_intermediate_rows` 和 Engine PMR 内存；计数单位和触发点固定：访问以路径状态出队、边以每个实际源-PC-解析候选、路径以生成的有序前缀计，去重前计数以防 bag 放大绕过限制。每次范围枚举、符号精确比较、事实扫描、候选分叉、证明复制与排序均计入 work，所有中间行、索引、frontier 和路径证据都使用 Engine 管理的 PMR；字段加法必须 overflow-safe。解码器若无法准确输出失败前工作量，不能伪造数值，记录为可观测下界，并在取消/预算量子上先解决其可中断接口。周期性检查取消和 deadline，包括无命中扫描、长字符串比较、排序、向反向索引插入和证据物化。

## 4. 证明与 ABI/CLI

现有 `dmg_binding_path` 是关系树左右侧（32）而不是调用链；`dmg_relation_link_v2` 只有两个实体端点，既无 PC/引用域，也无法把一组 hop 组成一条 path。不可复用它们伪造完整路径。为新 plan 增加带 size 校验的新版 getter（名称/布局待 ABI 定稿）：路径数量、路径头、逐 hop、unresolved frontier、expand profile。每条 path 至少含 seed、endpoint、hop_count、输入 tuple/角色身份和 uncertainty；每个 hop 含：原 caller occurrence 与 MethodDef ordinal、caller method_ref、dex_pc/code_offset、opcode、同来源 target MethodRef index、解析后的 MethodDef occurrence+ordinal、候选总数及范围完整性/歧义，incoming 仍照原调用方向记物理边。前沿诊断含发现处 caller+PC+ref、失败或不完整原因、深度和输入路径定位，禁止默认零值冒充已知引用。

Result 和每个 Batch 对路径/文本/节点数组按值物化，并持有 Query、SourceSet 和 Engine；调用方释放 Engine/Snapshot/Query/Job 原句柄后，最后一个 Result/Batch release 前借用视图有效。返回 size 不符、索引越界或 unsupported 时不写输出。旧 Job/Result/operation-profile getter 对包含 expand 的计划须一致地明确 Unsupported，除非所返回信息本身能完整表达新语义且契约明确允许；不得静默只暴露 endpoint 而丢失路径/未知诊断。不要改变既有公开 struct 的布局。新增 Job 终态/算子统计必须区分 entity scan、method scan、visited path states、decoded methods、edge candidates、resolved defs、complete paths、unresolved/unknown frontier，不把不同单位加成“总方法”。

CLI JSON 使用新版 profile 和独立 `paths:[{seed,endpoint,hops:[...]}]` 分组及 `frontiers:[...]`，输出每个值的 source occurrence、PC、引用域与不完整原因；endpoint 结果可附多条对应路径。普通文本、JSON 规范输出及真实 C 消费者都要读取新版 getter；Output limit 不得先截去决定 Unique/TopN 的候选。

## 5. QueryID、兼容与验证

只要任意 relation 节点含 expand（即使最终 root 是 MethodDef 或先 join），设置专门 `contains_expand` 并使用独立域 `DexMeguviz:QueryIR:expand-v5` / `query:v5:`，避免修改既有 v1/v2/v3/v4 字节与 capability 判定。确认无冲突后分配独立 capability bit，并将普通 invoke 事实需求纳入 demand_mask；`dmg_capabilities()` 和 CLI 同步公布真实支持。`encode_relation` 只对 expand 节点编码固定枚举值和全字段：方向、边类型、解析/循环策略、output、min/max depth、scope（set 按现有 canonical 规则）、walk/emit 谓词完整帧、各 traversal 预算以及子节点。语义默认值统一显式编码；不同策略/预算不得同 ID，JSON 字段顺序、等价 scope 顺序归一，同一 bag 分支顺序不能重排。Snapshot/source identity 不放 QueryID，但执行结果与缓存 key 必须绑定 snapshot/occurrence、scope completeness 和事实版本。人工固定 canonical 字节与 SHA-256 作 golden，且验证旧四个 profile ID 不变。

## 6. 必备样本与测试

自有可重建 DEX 样本：A 在来源0通过 PC 0 和 PC 3 调 B；来源1与来源2各定义同完整符号 B，B1 调 C1、B2 调 C2；各个被调对象位于其他来源。`max_depth=2, min_depth=2` 的 all-definitions 路径 bag 应为4条，分别包含每个 A PC、对应 B occurrence、B 自身 PC、C occurrence，端点集合为2；不要只断言数量，独立读取原始 opcode、method_ref、symbol、目标定义与原始 PC。复制完全相同的 B DEX 到另一个 source occurrence，应增加独立分支。再加入其他 owner/重载或 proto 不同的 B，不得误联接。

另外至少覆盖：

1. `max_depth=0`/min_depth 取值、直接调用及两跳、outgoing/incoming 方向互相交叉对照；错误 JSON/type/空输入/不支持边或解析策略必须显式拒绝。
2. `A→B→A` 深度边界；菱形 A→B/C→D 在 path bag 保留两条、endpoint set 只一个 D 且路径分组保真；每个同 caller 双 PC 保留。`max_depth` 是正常语义完成，不标预算失败。
3. 有/无声明范围、缺失 slot、无定义外部引用、半完成 Dataset、walk/emit false 与 Unknown、no-body、两种 Unique 身份、Exists 正见证但 Partial、Unique 一项加未知、两项加未知与 TopN 后来源更优。
4. 深/宽循环、大扇出、max_work/visited/edges/paths、中间行与 PMR 故障注入、取消/deadline、损坏位于早期有效 hit 之后；均不提交成功的部分结果。取消量子和计数每种至少前/中/尾覆盖。
5. 真实 C 消费者检查旧 getter Unsupported、不写 buffer、所有新 getter 错误 size 和边界，Job EOF/终态，Batch/Result 在原 Engine 等句柄释放后仍能读两条独立路径与诊断；ASan / 分配台账恢复。
6. 固定人工 QueryID 字节 golden，scope、方向、深度、解析/循环、谓词、path/endpoint、budget 各改变 ID；顺序别名和旧 v1–v4 回归。独立 Python 从原始 DEX 构建完整边/符号/路径 oracle，与标量执行逐 path 对比；篡改 PC、target、source、顺序、候选数和 completeness 的证明均被拒绝。有限 fuzz 覆盖 cycle、多源歧义与错误预算，不把成功随机运行当完整正确性。

## 7. 主要代码落点与同步边界

- `src/query/ir.hpp`、`src/query/compile.cpp`：typed 节点、参数、capability、版本域、完整 canonical；不改变旧 profile 的枚举/字节。
- `src/facts/use_relations/use_scan.{hpp,cpp}` 与 `src/facts/method_facts.*`：按需完整方法调用事实和可观测预算；incoming 反向索引按需建、来源绑定。
- `src/execution/reference/evaluate.{hpp,cpp}`、`relational.inc`、`entity.hpp`：有序路径、分组证明和 frontier 的 PMR 结构，标量遍历、多分支、scope completeness、去重和上限；不能让旧 `distinct()` 仅保留一条代表而丢其他展开证明。
- `include/dexmeguviz/dexmeguviz.h`、`src/c_api/{runtime.hpp,api.cpp,query_execution.cpp,job.cpp}`：新 getter、生命周期、终态、旧接口防误读与 profile。新增 ABI 符号按现有显式导出策略更新；不得扩展旧 struct 并破坏 size 检查。
- `cli/main.cpp`、契约与 ADR、`tests/native`、`tests/abi`、`tests/integration`、独立 fixtures/oracle、fuzz harness、CMake、backlog/evidence 同步。v5 相关信息必须在 CLI 和真实 C 消费者测试通过后才对外宣称。

P1-08 还要求完整 Q01–Q12，BoundedExpand 首版及 Q07 通过也只能更新其进度，不能单独把 P1-08 标为 done。
