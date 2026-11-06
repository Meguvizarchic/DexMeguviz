# 按需反向引用计数与索引（隔离实验 v1）

这是 P1-07 的受限实验，不是完整反向关系查询、稳定 ABI 或生产索引。`dmg_snapshot_reverse_count_v1` 对一个快照内指定 `source_index` 和一种 string-use / invoke-site / field-use，按 `(target_domain, target_index, extra_proto)` 返回该本地引用对应的使用点数量。结果是该来源 occurrence 的静态 DEX 使用点数，不证明全局范围、运行时解析、目标定义、ART 或业务含义；相同字节的不同 occurrence 和不同 Dataset 分开构建。`method_and_proto` 必须提供有效 proto，普通 method、field、string 和 call-site 的 extra 必须为 `UINT32_MAX`。不返回调用者或 PC 列表。

首次明确请求时，完成 checked 前向扫描，将完整结果在私有临时空间复制并按完整键排序，成功计数、最后取消检查及发布后才成为缓存。损坏、未知、资源/工作限额、分配失败或取消不返回计数、不发布可复用半成品；再次请求会重新构建。同一 Dataset/source/kind 的已发布索引用于后续真实查询；不同 target 共享它，不同 source/kind、不同 Dataset 或不同 Engine 不共享。默认查询、CLI、JNI、Job 和批量不自动调用该索引；另有独立显式的方法、字段及字符串 target_ref 同步实验入口，它们使用同一 Dataset registry，并分别限定形状、作用域和结果语义。

`dmg_snapshot_reverse_profile_v1` 返回该 Dataset 的 `build_attempts`、成功 `builds`、失败 `build_failures`、成功 `reuses`、`published_indexes` 和 `published_records`，计数在 `UINT64_MAX` 饱和。尝试只在查缓存未命中、开始构建前增加；构建、失败和复用只在对应真实路径发生。无反向请求的前向查询会留下全零 profile；这仅覆盖本 registry 和已核查的当前核心实现，不能代表外部扩展或未来绕过 registry 的其他索引。输出指针在失败时不写，profile 需要精确结构尺寸。

选项必须使用精确结构尺寸和 ABI 版本；`max_work` 上限100000000，`max_records` 上限100000，均须非零。工作量计 registry 条目探测和插入、checked 扫描工作、复制记录、排序比较和计数二分比较；查询缓存时先计入原构建工作，再计本次 registry 探测及二分工作，所以缓存命中在紧预算下可能被保守拒绝，不承诺与重建的精确阈值等价。`max_index_bytes` 约束索引 UseRecord 的逻辑字节，不包括 vector 容量、registry、临时空间或进程 RSS；所有 Engine 所有的临时和索引分配仍由 Engine 账本约束。多个已发布索引保留至 Dataset 最后引用释放，没有逐项淘汰。

同步调用接受协作取消回调；等待同 Dataset 构建互斥锁时轮询，扫描、复制、比较和发布前检查。取消是协作式最后检查，不保证停止一个已完成提交；回调不得重入任何 reverse API，当前线程重入明确拒绝。调用者须保持回调上下文、选项和 snapshot 句柄在调用期间有效，且借用 DEX 字节按原契约不可变。回调不得等待另一个试图访问同一 registry 的线程，否则可能自行死锁。已关闭的 snapshot/Engine 不再接收新 lookup；入场后与关闭并发的调用可以完成，调用者应保活句柄，profile 仍可在关闭但未释放时读取。Engine `shutdown(cancel_jobs)` 只取消 Job，不自动取消此同步入口；需要取消回调。

无反向请求时 Dataset 仍内嵌 registry 与互斥量，其控制块增大并计入 Engine 账本；紧预算下旧的快照打开阈值可能变化，不能宣称资源阈值完全等价。

索引和计数跟随 Dataset 所有权，所有读取、构建和发布由互斥锁保护，不跨 Dataset 复用；不承诺公平性。实验 C 消费者和受控多线程样本覆盖前向零构建、真实计数/缓存命中、预算、取消、相同字节不同来源、不同 Engine 和快照、损坏后重试、账本回收、关闭入场、用户回调重入及并发等待取消。除明确记录的独立实验关系入口外无自动 QueryIR 接线；没有性能评估、ABI 冻结、Android/ART 装载或完整 P1-07 验收。


## 逐事件分页（实验 v1）

`dmg_snapshot_reverse_page_v1` 使用同一 Dataset/source/kind 索引和相同 target 域、索引及 extra proto 约束，复制固定值事件到调用方缓冲。记录包含 source_index、use_kind、caller ordinal、caller method_ref、DEX code-unit PC、opcode、code offset、target domain/index 和 extra proto；不包含字符串/成员名称，不解析运行时目标。每个已完成结果按 caller ordinal、PC 升序稳定排序，相同 target 和不同 PC 不折叠；相同事件值的排列不可区分。source_index 只对当前快照有效，重复 occurrence 分别查询。

capacity 上限4096，0允许事件指针为 NULL，并在成功时返回0条和总数；offset 可为0到 total，等于 total 表示成功空页，大于 total 返回 InvalidArgument。每页的 out_count、out_total 和所有事件缓冲在失败时均不改；调用者需提供有效、互不重叠的输出区域。事件为纯值复制，返回后无需保留索引、snapshot 或 Engine；调用期间必须保活句柄。已入场的调用与 snapshot close 并发时可以完成，与旧 count 一致；后续请求返回 Closed。多次按 offset 请求须使用同一 Dataset/snapshot 和相同 source/kind/target，不能把位置当持久 token、跨快照复用或作为全局完整性证明。

页的定位、最多4096条暂存复制和索引发布都在受控操作内完成；首次构建过程中分页越界、预算、取消、分配或数据错误均不会发布该次新索引。既有完整索引在一次分页失败时仍保留但不计成功复用，输出也不改变。页暂存使用 Engine scratch 账本，不受 `max_index_bytes` 覆盖；每个已输出记录还需一个工作单位；该调用会实际支付此成本；成功发布时仅保存扫描、索引复制/排序与插入成本，不把首次 registry 探测、二分定位或页复制计入后续复用的历史构建工作。成功后的最终缓冲复制不再检查取消，避免将部分写入变成错误结果，取消仍是协作式最后检查。

为保证事件顺序，索引排序在 target 域/索引/extra 后增加 caller ordinal、PC 及其余记录字段作为确定性打破平局；旧 count/profile 的含义保持，但排序比较数量和分页暂存/读取会改变工作、内存及紧预算失败阈值，不承诺与迭代82相同。相同 1024 调用固定夹具、Windows MSVC Debug 的独立新旧 C 链接探测中，count 成功的最低 max_work 分别为迭代82的7198和此候选的12470；这仅是该环境与夹具，不代表其他实现或模式的阈值。同一已发布索引、两条事件固定夹具的 Windows Debug 探测中，缓存 count 和读取两条页面的额度相差2个工作单位（原始数值以本轮证据为准）；差值仅反映该夹具的两次复制计费，不推广到其他环境。该分页 C 入口本身不自动接入查询；另有独立显式 target_ref 同步实验，JNI 和 Job 不自动使用，不证明 ART/运行时绑定或完整 P1-07/P1-08 验收。
