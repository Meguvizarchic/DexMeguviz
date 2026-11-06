# 显式反向索引 target_ref 连接（内部实验候选）

`dmg_query_execute_reverse_target_v1` 是独立、同步、实验性 C 入口；不改变原 `dmg_query_execute`、Job 或 `dmg_multi_execute_v1` 的选择与语义。它仅接受 v4 的直接 `join(target_ref, scan(invoke_sites), scan(method_refs))`，保留原查询 ID、来源、逐 PC 事件、左/右连接顺序、proof、Unknown 和局部 scope。两侧顺序反转、union/重复候选、其他关系、流式及新于 v4 的能力组合 均明确返回 Unsupported，不能静默回退。合法空输入无需构建索引。

runtime 从所传 snapshot 持有的同一 Dataset 获取 registry 和只读来源；实验入口不能由调用方指定另一 registry。先按旧路径完整 checked 扫描并物化两个直接 scan，目标按本地 source occurrence + method_ref 编号匹配；以反向分页索引查找普通 method_ref 和每个有效 proto 的 method_and_proto，call_site 不参与 target_ref。对所选 checked 前向事件和所选目标引用的交集逐字段核对，匹配遗漏、字段不符或重复匹配拒绝；页面中不属于所选前向事件的记录会被跳过，未逐条验证这些记录或整个索引，仍依赖所请求来源与目标的索引正确性；输出顺序仍依原左侧事件及右侧候选的顺序。索引本身的查找不代表运行时方法绑定或跨来源符号等价。

旧连接对每一对候选的逻辑 `max_work` 计费和检查点按旧顺序分段补记；结果及 QueryID 无须更改，但这不是跨所有计划、所有故障与真实异步取消的等价证明。本入口只提供同步调用，不提供独立 Job 或批量 opt-in，旧 Job/批量仍不触发索引。执行首次建立或复用索引时，extra 计算、分配、锁竞争和取消检查会改变物理工作、资源消耗和失败时点。返回成功不承诺更快；无需查询的空集合可避免索引调用。

选项必须为精确 struct_size/ABI 和非零上限：`max_index_work` 是每次分页调用上限、`max_index_bytes` 和 `max_records` 是单个反向索引上限，`max_page_calls` 限制整条 join 发起的分页次数，`max_adapter_work` 限额额外定位和校验逻辑工作；工作单位不覆盖分配器、进程 RSS 或墙钟。任意一项不足返回 BudgetExceeded，不回退旧 join；额外结构使用 Engine scratch 账本、已成功构建的索引保留在 Dataset，故后续失败不会撤销已经发布的完整索引，紧内存状态可能不同。同步入口的 QueryIR、选项、输出指针和 snapshot 必须有效，写入区域不得重叠；失败时 out 置 NULL，不发布结果。

各上限分别要求 `max_index_work` 和 `max_adapter_work` 不超过 100,000,000、`max_records` 不超过 100,000、`max_page_calls` 不超过 65,536。同步入口无外部取消回调；内部控制检查点增多，不代表可异步取消。

两个 scan 已成功完成后，若任一侧超过 4096 条中间结果，返回 Unsupported；扫描期间更早的预算、损坏和取消错误仍优先。查找所有 proto 可能触发页调用上限。预算、内存或取消错误不可当成空结果，原 Job 的取消与其他旧入口保持现有合同；额外检查点的真实时间、线程调度与系统 OOM 不保证等价。临时实验不接入 JNI、CLI、BIL 或生产配置，不宣称性能收益、完整 P1-07/P2-01、全部 QueryIR 或 ART 验收。

固定 DEX 字节 oracle 和 C ABI 消费者随实验候选提供并可通过 CTest 重跑；它们仅证明所列主机样本和拒绝边界，不构成全面性能或完整事实验收。

测试构建专用屏障在首次反向页与正式结果物化时触发确定性分配故障，验证未发布结果、完整索引的受限保留及资源回收；这是注入故障，不是实际系统 OOM。C 消费者另验证结果在释放原 snapshot、query 和 Engine 句柄后仍可读取。

字段使用点的独立显式实验入口与本方法入口分开，见 [字段反向 target_ref 合同](reverse-field-target-join-v1-draft.md)。

独立字符串实验入口与本入口分开，见 [字符串反向连接合同](reverse-string-target-join-v1-draft.md)。
