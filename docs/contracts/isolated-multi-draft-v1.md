# 私有多规则会话草稿 v1

`planner::IsolatedMultiSession` 是内部 C++ 草稿，不属于 C ABI、JNI、CLI 或生产兼容承诺。它通过已有 SourceSet 打开逻辑建立自有 Engine 与快照，只复制调用方显式给出的来源；外部不取得 Engine、Snapshot、Query 或 PMR 资源句柄。指定 scope_complete 仅表达调用方对这批来源的声明，不能推断整个应用或 ClassLoader 完整。

同一个会话的 add、execute、close 和静止账本采样由同一 mutex 串行化；不接受取消 callback，不支持重入。正在并发调用的线程必须自行保证会话对象仍存活；close 等待当前执行离开并拒绝后续 add/execute，关闭本身不提前释放会话持有的快照。不同会话的 Engine、规则与缓存彼此独立。

每次 execute 选择已编译规则，使用 Engine 控制资源保留临时缓存，调用现有参考执行器并顺序处理。缓存适用于列明的直接计划和限定单 Scan 的 v3/v17 Filter/Label 图，要求相同来源 occurrence、有效 scope、完整性、profile、能力和精确需求；其他关系图、未识别 profile、array_data 与不满足条件的计划回退标量。规则各自保留工作限制和错误/Unknown，不把缓存存在当完成。缓存导致的预算失败只在尝试结果尚未向调用者发布且释放缓存后整体标量重试；普通 OOM、取消和内部错误不以重试掩盖。

返回的 `IsolatedBatch` 保持 Engine、SourceSet 和已选计划直到批次销毁；只返回标量、值对象或与批次同寿命的只读字符串视图，不暴露 PMR 容器或 Engine 原生句柄。可查看每规则状态、覆盖范围、进度、实体键、来源、投影文本、绑定、路径、连接、见证、scope 和算子 profile。使用事实结果通过对应 use accessor 获取原始事件，metadata entity accessor 不接受 use key。结果之间不会共享可修改的 Query 执行状态。

该实现是内部探索：Result 持有 reference scratch，而现有公开 C ABI 独立执行会物化到 result 账本；同时持有多个批次也会占用预算。因此不声称与公开逐次调用在所有资源阈值、错误先后或内存峰值上等价。会话对象与 mutex 的运行库内存、线程栈、底层分配器元数据及 RSS 不计入 Engine 账本；返回的字符串视图不可超出批次生命周期。该私有会话不提供公共批量 ABI、并发取消或持久缓存；实验性 C 多规则入口另见 [multi-query-c-v1](multi-query-c-v1.md)。Android/ART 与完整 P2-01/Q12 尚未验收。

## 逐规则正式结果物化（内部候选）

`IsolatedMultiSession::execute_one(id)` 在同一会话互斥锁内查找已编译规则，并调用现有 `dmg_query_execute` 路径：每次独立执行并物化到 Engine 的 result 分类账本，不使用共享 facts cache、不重试。返回的 `MaterializedRule` 以 RAII 持有 C 结果；销毁或移动赋值后释放，底层 Engine、来源及 Query 在结果存活时保持。可用的结果、行、图绑定/证明绑定、路径、连接和见证接口按现有 C getter 返回状态码；未支持的 getter 保持 Unsupported，借用指针仅在对应 `MaterializedRule` 存活且未移走前有效。执行调用成功不等同查询覆盖完整；必须查看结果中的 execution_status、coverage 和 decision。调用失败不返回结果。`stats()` 提供原 Engine 多原子采样，静止后可比较分类账本，不是 RSS 或并发事务快照。

本入口为标量执行基线，不提供多规则共享加速或公共批量 ABI。单个规则执行与独立 C 查询经过同一实现，但会话本身的规则持有、控制分配和调用顺序不同，不能推断所有资源阈值、系统 OOM 或并发调度等价；同步 C 执行不可取消，close 与执行由会话锁串行。固定双来源样本对照方法、连接与半连接的实体、来源、绑定、路径、连接、见证和结果账本增量，并测试不完整范围、ResultLimit、work budget、保留结果触发实际 Engine 预算及释放回基线、会话关闭后保活。见本轮独立证据；不代表 Android 或全 P2-01/Q12 验收。

## 重基至当前核心的防护

缓存仅接受已列举直接计划，及单个 method_defs Scan 加 Filter/Label 祖先的 v3/v17 图；需求限定为 `strings`、`invokes`、`fields`、`numeric` 子集。`array_data`、`switch_targets`、`branch_targets` 和任何未知 demand 位，以及其他图形和 v16/v18 等未列举 profile 均退回标量。UTF-16 文本条件各自独立执行，只在来源 occurrence、scope、profile、capability 和精确 demand 等键相同的情况下共享与文本无关的方法事实。缓存启用与关闭的固定样本比对了行身份和见证、作用域、各规则逻辑工作及资源回收；不代表该私有 scratch 入口自身提供公开 C 结果批量物化，也不代表所有错误交错或全部 P2-01 验收。

## 共享结果的正式物化候选

`execute_materialized(ids, cache_bytes, max_cache_work)` 在会话互斥锁内执行原受限共享计划，随后调用与 `dmg_query_execute` 同一内部函数将每个已计算结果物化为正式 C Result。真实缓存命中由批次 profile 报告，不承诺所有计划都共享；不受支持的 profile、关系图或 demand 沿缓存合同标量回退。每个结果保留其 Query、SourceSet 和 Engine，可按下标单次 `take` 后独立释放；重复取同一项明确拒绝。关闭会话或销毁批次后已取走的结果仍有效。

结果在全部规则评估和全部物化成功后才一起发布；规则评估失败报告首个失败项的序号、内部错误码及偏移/PC，物化失败报告序号与 C 状态，不发布任何结果。分配、验证或会话关闭也可能在开始/物化前失败；批次本身及中间资源随异常释放。`ResultLimit` 是带受限执行状态的成功结果，不视作整个批次失败。该内部接口不接受取消回调，不提供公开 ABI；查询原有 scope、coverage、decision、projection、来源及见证以正式 getter 返回。

批次的各规则 scratch 结果与已物化的 Result 可能同时驻留；共享缓存尝试也计入 Engine 分类账本，因此预算阈值、峰值及错误先后不保证等同于逐次独立调用。缓存占用导致的执行预算失败仅在全部尝试均未发布且没有 OOM/取消/内部错误时释放并作原有整体标量重试；物化阶段失败不会重试。事务性只表示不发布部分批次，不保证恢复已发生的 CPU 工作。测试覆盖固定输入，不能推广为全部故障或并发调度。
