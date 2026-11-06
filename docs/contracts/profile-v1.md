# 诊断输出统一外层 v1

CLI新增profile_v1外层，旧query/query_profile字段保留。producer标识native-query；phase=planned时只有plan且runtime=null；phase=executed时保留实际QueryID、demand/能力和观测计数。logical_work_units是逻辑计费，不是CPU时间/物理解码次数/RSS；fact_requests、methods_decoded和code_units沿用现有核心口径。来源完整性与unknown_rows单列。

展开的reverse_index_events按节点报告实际built/reused次数；其他路径未观测时为null。retained_index_bytes和cancel_check_count目前未统一计数，明确null，不用0冒充已测。scope完整性不能在explain阶段推出。一次性SQL的profile_v1使用producer=desktop-sql，区分来源准备、SQL会话open/prepare/first_step/query/close。驻留保留其原有profile/reuse/stats结构，其64位计数仍为十进制字符串；映射时不得改变单位或把first_step当完整first-answer。未宣称全平台所有指标齐备。

驻留同步与后台 JSONL 的成功 `final` 响应现在同时携带 `profile_v1`；这里“成功”指读到终态，SQL 本身仍可能失败或取消。旧 `profile`、`reuse`、`result`、状态及 ack 协议保持不变，新增对象沿用既有扩展字段方式。

`producer=desktop-sql` 来自写出该响应的桌面 SQLite 适配器，与一次性 SQL 相同，不是输入数据自报的生产者。`phase=executed` 表示已取得任务终态；它不表示一定执行过 prepare/step。该终态不保存 SQL 文本及原请求额度，因此 `plan=null`，不补造 QueryID 或计划。`runtime.query` 直接映射该次 `SqlQueryProfile`：sequence、elapsed_us、prepare_us、first_step_us、progress_callbacks、rows_staged、rows_committed 均以十进制字符串输出；SQLite 状态码为整数，三个观察/准备标记为布尔值。没有 profile 的排队取消或更早失败令 query=null；没有调用 prepare 或首次 step 时，对应耗时/首次 step 状态为 null。实际观察到的零微秒仍为字符串 `"0"`。

`runtime.statement_reuse` 映射终态保留的会话累计 prepare_attempts/cache_hits/automatic_reprepares、cached 标记；没有该次 SQL profile 时保守输出 null，不把默认零值当作当前观察。`estimated_retained_statement_bytes` 来自既有 SQLITE_STMTSTATUS_MEMUSED，是 SQLite 对已保留语句的近似统计，不是 native 索引、Engine 总账或 RSS；不改名充当 retained_index_bytes，也不由命中数推断性能收益或完整 warm 延迟。计数及估值均保持十进制字符串。

驻留 final 没有独立采集来源准备、会话打开和关闭耗时，故该对象的 source_prepare_us/session_open_us/close_us 为 null；原同步 stats.open_us 与显式 close 响应的 close_us 仍按原口径读取。retained_index_bytes/cancel_check_count 继续为 null。后台任务可能在 SQL 内部成功之后、终态发布之前被取消；此时顶层 execution_status 与 runtime.query.execution_status 各自保留终态和内部 SQL 尝试的真实状态，rows_committed 也只表示内部严格 SQL 提交，不能据此交付 result=null 的任务结果。
