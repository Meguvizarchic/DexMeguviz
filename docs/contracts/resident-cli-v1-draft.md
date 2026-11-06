# 桌面 SQL 驻留命令行（内部草稿）

启用 `DMG_WITH_SQLITE` 后可构建 `dexmeguviz_sql_session`，参数为一个 raw DEX/APK 主输入，可用 --source/--resource-source追加有序来源，默认累计输入限32MiB，--max-input-mib可显式调整；Windows 使用宽字符路径以支持非系统代码页字符。默认创建不完整来源范围快照，--scope-complete可显式声明完整范围及单线程同步 `ResidentSession`，不会安装 APK、加载 Android 类或打开网络。标准输出是 UTF-8/ASCII JSON Lines；首行 `ready`，此后每个请求产生一个响应。单行最多 65,536 字节，超长行被完整丢弃并返回 `SQLITE_TOOBIG`；键须严格匹配，重复键、错误 UTF-8、非法数字或无效代理项拒绝。

请求包括 `submit`（`sql`、可选 `params` 数组，null/有符号64位整数/UTF-8文本/BLOB标签（blob_hex），允许文本 NUL；精确整数可写成 `{"integer":"-9223372036854775808"}`；可选 `max_rows`、`max_bytes`、`max_progress`）、`run`（同步执行最早任务）、`final`（按 `id` 读取已保留终态）、`cancel`（仅取消排队任务）、`ack`（确认终态）、`stats`、`close`。SQL 本身不允许 NUL；单次结果逻辑限额最高 1 MiB。队列固定最多16个未确认任务，输入逻辑额度 1 MiB，结果预留 16 MiB，单缓存语句额度 1 MiB。每个提交成功返回非零十进制字符串 id（请求也须使用字符串），拒绝时不创建任务。`run` 的成功仅表示已产生终态，SQL 结果必须读取 `final.execution_status`；失败终态的 `result` 为 null。

SQL 整数单元以 `{"integer":"十进制值"}` 返回，避免 JSON 客户端丢失 64 位精度；profile、累计计数与字节量也以十进制字符串返回。`final` 可重复读取，不消耗记录；`ack` 才释放对应槽位。存在排队或未确认终态时 `close` 返回 BUSY，不关闭会话；成功关闭响应含十进制字符串 `close_us`，是关闭操作的单调时钟耗时，不是 CPU 时间。结果带 snapshot_id、调用方声明的 partial/declared_complete 来源范围和输入/来源数量；原生 profile 包含准备、首次执行及语句复用计数，仅作单次壁钟观察。输出限制 8 MiB；序列化超限或不能转成有效 UTF-8 时返回错误并保留终态。协议无隐式安全擦除或断线持久化；未确认任务时 EOF 进程退出码 2，消费者必须在连接关闭前读取并确认终态。无后台线程、跨进程恢复、MCP、RSS 上限或 Android 运行声明。

例如依次发送 `{"op":"submit","sql":"SELECT ?1","params":["hello"]}`、`{"op":"run"}`、`{"op":"final","id":"1"}`、`{"op":"ack","id":"1"}`、`{"op":"close"}`。只有完成且确认后关闭才为正常结束；来源范围不完整不构成全局不存在或唯一的证明。

可显式选择独立的 `--background` 模式，详见 [后台 JSON Lines 合同](resident-background-cli-v1-draft.md)；本文件的同步请求与退出约束保持适用。
