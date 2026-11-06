# Engine / Job / Batch 执行契约

当前实现覆盖method_defs的共享JSON/typed标量计划和按需指令谓词，详见method-query-v1.md。Query在同一Engine内跨Snapshot复用；每次Job的取消、deadline、进度、队列和临时资源独立。完整关系DAG继续实施。

## 资源与生命周期

Engine使用分类PMR resource，先reserve再allocate；真实请求字节按source/facts/scratch/query/result/control计账，失败rollback，deallocate归还。预算不是RSS/PSS。Result/Batch保持Source、EngineState和resource，直到最后引用释放；Job终态不提前回收保留结果的费用。

Engine根对象、标准运行库错误诊断、线程/同步原语内部内存、线程栈、allocator元数据、CLI输入/输出缓冲不纳入managed-bytes承诺。活动Job数量有独立上限；默认4、最多64。原同步入口默认16MiB source，显式Engine的默认source上限128MiB与owned预算256MiB可由调用者配置。borrowed地址字节有独立上限，不伪称由核心分配。

不同分类与total是多个原子采样；并发读数不保证事务一致，静止后各项相加精确等于owned。peak指managed requested bytes峰值，非进程内存峰值。

MSVC容器调试代理会在noexcept构造中分配，不能安全传递PMR预算异常；项目target统一使用_ITERATOR_DEBUG_LEVEL=0，实际ASan与显式checked reader提供本轮内存验证。没有修改BIL的编译设置。

## 有界执行

每Job一条worker线程，由Engine admission限制数量。batch_size为1..4096，max_queued_batches为1..16；队列满时producer等待，输出端最多另持一批。无排序的直接 Exists/Unique 扫描，以及不含 use 关系的可流式关系图，在可靠根候选形成后立即发布单行 provisional Batch，batch_size 是每批行数上限；已发布候选与正在扫描的数据可能同时占用 result 和 scratch 账本。其他参考路径在发布前持有有界候选集合（最多max_results，TopN为N），它独立计入scratch预算，不受队列批次数限制；不是P2的优化流式计划。无消费者时deadline/cancel仍可解除等待。

Job next为单消费者；cancel/status/wait可由另一个持有有效引用的线程调用。wait/next timeout只结束等待，不取消任务。deadline_after_ms是创建时相对steady_clock deadline；本版最大24小时。取消在方法之间、每1024个文本比较/前缀回退工作单元及结果文本复制过程中检查；allocator调用、同步source准备/编译Query不提供可抢占承诺。

终态只提交一次，cancel之后不修改已终态结果。worker终态和thread启动失败都从Engine的weak registry移除控制块，避免allocator持有Engine形成循环。Engine release只释放当前引用；shutdown先关闭admission，再可选发出取消。shutdown返回不代表任务已经停止。

正常 `cancel` 与终态提交以 Job 锁线性化；提交前已观察的取消或 deadline 会反映在终态，先前已产生的 BudgetExceeded、CorruptInput 或 ResultLimit 保持优先。队列满时最多按 50 ms 的重检间隔检查取消和 deadline，以避免 shutdown 或异常回退通知落在等待前而丢失；该间隔不承诺操作系统硬实时调度。极端互斥锁异常时 C ABI 吞获异常并以原子设置取消作 best-effort，无法保证与并发终态的先后顺序。此前已发布且可取得的 Batch 仍为 provisional，读取不会减少最终已发布候选计数。

Snapshot close拒绝新Job，已通过admission的Job继续持有来源。最后job_release请求cancel并join该worker，随后销毁未交付队列；已交付Batch不依附Job的临时状态。callback不在内部锁中调用；borrowed lease callback必须保持不可变性、线程安全、不抛异常。

## 结果提交

每Batch都是provisional的可靠候选子集，coverage保持Partial。可流式的无排序 Exists/Unique 中，即使 batch_size 大于1也逐条发布，队列满时暂停后续扫描；已触发的 ResultLimit 不被随后到来的取消覆盖。不含 use 关系的图查询中，Exists 仅在根算子形成可靠行后交付；Unique 仅支持 scan 或从 scan 经 filter/label 的不重复身份链。join、union、distinct、group 等 Unique，默认 use v4/v7 关系及排序/TopN 保持原子求值。显式 use-stream-v9 允许无排序 use 根在完整检查并提交单方法统计后交付见证，Unique 的 max_results=1 回退原子执行；其同步和 Job 采用同一逐方法计费顺序，但与 v4 的紧预算或后续损坏错误先后可能不同。visited 计数包含已经开始访问、但随后因取消而未完成谓词求值的记录。读取全部批次后还必须检查Job终态：Complete、Cancelled、DeadlineExceeded、BudgetExceeded等不能由EOF代替。存在性和非唯一性只基于已发布且可取得的witness；未发布的临时行不会计入最终候选数。

本轮通过真实C消费者和C++行为测试验证单队列背压、timeout、deadline、cancel、终态不可变、query复用、跨Engine拒绝、借用/FD来源、Batch保活和静止账本回baseline。完整指令算子取消、SQL、Android/JNI与真实设备延迟尚未验证。
