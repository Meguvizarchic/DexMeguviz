# Unique 单结果逐方法交付 v12

此 profile 是限定范围的本地工程能力，完整 P1-09 和稳定性验收仍未完成。显式 `required_capabilities:["unique_one_stream"]` 选择能力位1048576，并隐含原 use_streaming 位131072；同时写出两个名称得到相同规范化 QueryID。新身份使用 `query:v12:` 和 `DexMeguviz:QueryIR:unique-one-v12` 域，原 v9/v10/v11 的编译和身份不变。

隔离实验扩展：只接受无排序、Unique、max_results=1、entity identity、单个根 invoke_sites / string_uses / field_uses scan；扫描内支持现有适用谓词和范围。对应的三类 use 能力位必须与根关系精确匹配，跨类型显式需求返回 Unsupported；filter/label、join/union/distinct/group、排序、tuple identity、其他高级能力及 explicit order/join/group 均返回 Unsupported。此限制是当前证明边界，不是完整 QueryIR 或完整 Q09；执行侧同时校验能力位，防止内部手工构造不符合范围的 Plan 绕过编译检查。

一个方法的指令和 use 记录必须先完整 checked 并计费，才可发布该方法的可靠候选；最多首个候选以 provisional Batch 交付，必须读取 Job 终态。一个已发布候选不能证明唯一；后续失败不会撤回已交付 Batch。候选观察、扫描和图 profile 可在失败后保留，不应作为已交付数量或最终决策。

发现额外候选只形成暂定限额。同步与 Job 在最后归约时均执行保留行的 scratch 准备与同一逻辑工作计费，再检查取消；在此之前预算、损坏、取消或 deadline 可先失败。Job 在 Engine admission 与 Job 锁内再次检查取消/deadline，随后才将暂定限额提交为 `BudgetExceeded/ResultLimit`；锁先后决定竞争，终态提交后不再更改。同步入口按现有 C ABI 返回 `DMG_OK` 携带限额结果；Job 终态携带相应执行状态。ResultLimit 只可推断结果被限，不得视为 Unique 或否定结论。

每个候选的值、见证和关联在结果资源上完成，队列 push 成功后才增加已发布数量；失败销毁临时结果并归还资源。当前 v12 根 scan 没有 label/binding；旧 v9 label 的绑定复制失败仅作为共享发布路径的独立对照。已发布 Batch 可独立保活来源、Query 和 Engine。Job/消费者持有 Batch 会改变物理峰值，逻辑 max_work 相同不保证内存失败点相同。

测试只覆盖固定原创 DEX、指定谓词、有限预算和确定性竞争点；全量输入、所有谓词/资源交错、任意并发、Android/ART、设备和性能未证明。范围外能力仍拒绝；该验证不能代替完整 P1-09 或设备验收。

此文件描述尚未集成的 C 盘隔离草稿。字符串行只返回引用索引，本轮 UTF-16 字节核对不证明字符串值匹配或 Android 运行时行为。
