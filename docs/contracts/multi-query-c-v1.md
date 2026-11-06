# C 多规则批量查询 v1（隔离候选）

`dmg_multi_execute_v1` 是同步、实验性新增 C 接口；不改变 ABI 版本 1 的已有结构或函数，也不是 Job 流式批次。`dmg_multi_options_v1` 必须提供、结构大小精确等于当前版本、ABI 版本为 1，flags 为 0 或显式选择 `DMG_MULTI_FUSE_METHOD_ENUM_V1`，reserved 为 0。count 为 0–256，count 非零时 queries 必须指向相应数量的有效 Query 句柄；同一 Query 可重复，结果按输入位置一一对应。所有 Query 与 Snapshot 必须属于同一 Engine。调用期间调用方保持所有输入句柄及数组有效。

成功时返回一个持有所有正式 Result 的独立多规则批次和 `failure_index=UINT32_MAX`；ResultLimit 仍是带 `execution_status=DMG_BUDGET_EXCEEDED`、`reason=DMG_RESULT_LIMIT` 的成功 Result，调用方须逐个查看 coverage、decision、reason 和 profile。执行或物化失败时 `*out=NULL`，无结果可取得；先完整校验输入句柄，若校验失败则返回该阶段首个无效 Query 的索引；校验通过后先完成规则评估并返回首个评估失败项，最后按顺序物化并返回首个物化失败项。无法归因到规则的失败返回 `UINT32_MAX`，因此失败优先顺序不保证等同于逐项执行。`dmg_error` 是调用方持有的诊断副本；评估失败的消息为通用信息、偏移按内部执行器提供，物化失败保留其 C 错误。内部工作不会因原子不发布而被撤销。

多规则批次支持 retain/release。`dmg_multi_batch_get_result_v1` 每次成功都增加返回 Result 的引用：调用方须对每个成功获取的引用调用 `dmg_result_release`，即使多次获取同一位置而指针相同。独立 Result 保持其 Query、SourceSet、Engine 所需生命周期，批次、查询、Snapshot 和 Engine 的外层句柄释放之后仍可读取；借用指针有效期仍由所属 Result 引用决定。查询期间必须持有批次引用；批次不可变，持有有效引用的多个线程可读取和独立取得结果。伪造、过早释放或重复释放句柄不在契约内。

Snapshot 已关闭或 Engine admission 已关闭时拒绝启动；通过 admission 的同步工作可完成，与现有同步调用相同。此接口不支持回调取消、deadline 或运行中取消；Engine shutdown 的 cancel_jobs 仅适用已有 Job。SourceSet 的 scope 仍是调用方静态声明，并非完整 ClassLoader 来源证明。

`cache_bytes` 和 `max_cache_work` 分别限制临时缓存字节与缓存工作；任一为 0 则无共享。Engine 预算不足无法保留缓存时回退标量，`arena_budget_unavailable` 可观察；批次 profile 的 `physical_collects` 仅统计接入缓存的 Evaluator 发起的事实收集，不包含未接入缓存的图形或标量回退，因此不是整个批次的物理解码总数。`cache_hits`、`cache_builds` 及 `cache_work_charged` 分别记录本次缓存命中、条目建立和缓存工作，规则自身逻辑 profile 保持独立。已列举直接 profile，以及仅含单个 method_defs Scan 和 Filter/Label 祖先链的 v3/v17 关系图，在相同 source occurrence、全局与 Scan scope、实际作用域完整性、精确 demand、profile 和 capability 下可共享已完整复制的 strings/invokes/fields/numeric 事实。每个 Filter 的有效 scope 仅在该单扫描链中可安全归约到同一 Scan；未列举图形、profile、array/switch/branch 或未知 demand 回退标量。每个 Query 自己的文本匹配、逻辑工作上限、身份、scope 和结果状态独立执行。为避免并发预算变化掩盖已发生错误，公开入口不作批次失败后的整体重试。

当 v3/v17 的整个关系树仅含 method_defs 的 Scan、Filter、Label、Union 和 Distinct，且所有 Scan 的显式 scope 标记与规范化 slot 列表完全相同时，也可在该图内及同批符合原键条件的其他规则之间共享事实。顶层 scope 仍单独参与缓存键，扫描来源 occurrence 和实际完整性仍须一致；空范围、显式范围及默认范围不因碰巧选中同一来源而合并。只缓存 checked 原始方法事实，不共享谓词结果、Unknown 或行见证；作用域不一致、其他算子、其他关系、use 事件及未支持需求一律回退。此图形检查本身消耗 `max_cache_work`，耗尽则回退，不改变 QueryIR 逻辑工作计数。更大的缓存或新图形可改变额外内存峰值、极紧预算下的错误顺序和性能；各项使用者仍须检查自己的结果、状态和资源预算。

共享缓存、全部 reference scratch、中间 Result、批次和已返回的 Result 均纳入 Engine 分类账本；它们可能重叠驻留。预算阈值、错误先后及峰值不保证与单次逐项执行相同，账本不等于 RSS，多个调用共享同一 Engine 预算导致的竞争会影响预算结果。固定主机测试不证明全部并发、系统 OOM、Android 导出/装载或完整 Q12/P2-01；尚无公共稳定 ABI 承诺。

## 同范围 owner 分组复用

批量规则允许 `group_by_owner` 参与可共享图：整棵图的每个叶扫描必须都是 method_defs，且每个扫描的显式scope标记和规范化slot列表完全一致；分组输出 class_defs，外层可以继续使用已接通的 filter、label、union、distinct。限定的共享对象仍只是完整checked方法事实，group成员数、bag顺序、各角色绑定、分配策略、Unknown及最终决策各自由各规则独立计算。不同scope、field_defs叶、join、use事件、其他高位profile或未支持需求均回退原标量执行。

`cache_bytes`、`max_cache_work`、每条规则自身logical work与scope/能力键沿原合同；缓存arena不足或缓存工作耗尽回退，不把回退报告为命中。取消接口、失败原子性及额外内存预算边界不变；本扩展不承诺广义Q12、所有阈值、性能收益或Android运行验收。

# 多规则方法枚举单遍原型

`DMG_MULTI_FUSE_METHOD_ENUM_V1` 是 `dmg_multi_options_v1.flags` 的显式建议标志，默认 0 保持既有逐规则执行。仅当全部规则为 direct method_defs、query:v1、enumerate、无排序、无显式 scope、无继承/扩展/注解/方法类型、无取消回调，且所有 source 属于相同 Dataset 时进入外层逐 source/方法、内层逐规则的单遍；其余整体回退原标量路径。它保留每规则的 QueryID、逻辑 work 预算、Unknown、候选顺序、结果上限和独立错误；单遍不表示每谓词只算一次，也不表示所有指令只解码一次，事实缓存仍采用原独立额度/精确需求键。

Android 的 `MethodStream.queryMethodsBatch` 可对预编译的方法计划显式建议此标志，结果和限制见 `jni-method-stream-v1-draft.md`。内存分配交错会改变 Engine 紧预算下的失败时机和峰值；执行不支持取消。`dmg_multi_batch_v1` 仍原子返回且保留默认的首个规则错误选择。此原型暂不保证所有失败路径或并发环境等价。

验证：合成方法 DEX 和真实 B 站 9.14 classes14 各 32 组差分，包含每规则预算失败、结果上限、两来源、scope complete/incomplete、缓存开启/关闭；比较各规则状态、候选、证据和逻辑进度。现有 C 多规则消费者启用标志，通过范围回退、ResultLimit、原子失败与生命周期检查，未知 flags 被拒绝。有限样本，不代表完整 verifier、Android、ART 或生产。

Windows Release、classes14、6 条 BIL 方法条件、每模式执行20次的单次 ABBA 在并行负载下旧 491/619ms、新 404/439ms；未证明稳定收益，未计 native open/ZIP/绑定，不与 DexKit 对比。此前测试的 432/334ms 对 361/358ms 和轻负载 259/266ms 对 235/239ms 产生于最终代码之前，不能当作最终代码的性能。
