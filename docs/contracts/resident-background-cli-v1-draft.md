# 可选桌面后台 JSON Lines 命令行（内部草稿）

桌面显式启用 `DMG_WITH_SQLITE` 后，以 `dexmeguviz_sql_session --background <raw.dex>` 启用后台模式；不带 `--background` 的既有同步模式及其 `run` 协议保持原样。两者均支持有序raw DEX/APK和resource-source，默认累计32MiB输入，可显式声明scope和设置输入/Engine/SQLite heap额度，Windows 使用宽路径；不会安装 APK、访问 Android 或网络。后台模式首行 `ready` 增加 `"mode":"background"`，之后由主线程独占 stdout，每个完整请求返回一个 JSON 行；worker 不写 stdout。

后台模式沿用同步协议对单行、严格 JSON、参数类型、精确 64 位整数、SQL 和单次结果的限制：行不超过 65,536 字节，最多 256 个参数，SQL 非空且无 NUL，单次结果逻辑字节最多 1 MiB。固定最多 16 个未确认任务、1 MiB 输入逻辑额度和 16 MiB 结果预留；这些不是 SQLite、复制结果、线程栈或进程 RSS 上限。`submit` 接受后自动执行并返回非零十进制字符串 id，不需 `run`；后台模式的 `run` 明确返回 `SQLITE_MISUSE`。重复 JSON 键、非法 UTF-8 和超长行均拒绝，超长行会丢弃至换行后继续读取。

`final` 按 id 查看，不等待任务完成：排队/运行中返回 `SQLITE_BUSY`，终态可重复读取，只有 `ack` 才释放槽位；未完成时 `ack` 返回 BUSY。成功结果保留 snapshot、部分来源标签和 SQL 行；失败结果为 null。`cancel` 可取消排队任务或请求运行任务协作取消；最终状态以随后 `final.execution_status` 为准。底层 SQL profile 描述执行器本身，不得替代外层终态。`stats` 返回 queued/running/terminal 和逻辑配额，`interrupted` 统计所有 SQLITE_INTERRUPT（包括进度预算中断），不是用户取消次数。以上方法需取得内部互斥锁，终态读取和 JSON 格式化会复制结果，不承诺实时响应或常数时间。

必须发送 `{"op":"shutdown","cancel":false}` 停止接收新任务并排空现有队列，或使用 `true` 取消排队任务并请求取消运行任务；两种都保留终态直到逐一 `final`/`ack`。shutdown 后 submit 被拒绝，未 shutdown 或任务尚未确认时 `close` 返回 BUSY；完成所有确认后 `close` 等待 worker 关闭并返回 `close_us`。关闭和取消不承诺硬实时，调用者应按需轮询而非把 BUSY 当 EOF。

输出上限 8 MiB；终态序列化失败、超限或包含无效 UTF-8 时返回错误并继续保留终态。stdout 是易失传输，不是持久队列；写入失败进程返回非零，提交响应若未送达，调用者无法仅凭 stdout 判断任务是否曾被接受。EOF 时若仍有任务或未确认终态，进程以非零退出并在对象析构时请求取消、放弃余下终态；无任务时可正常退出。进程崩溃、断线和重启不提供恢复，调用者必须在连接存活期间读取并确认终态。后台会话底层的线程、来源、资源和析构限制见 [后台队列合同](sql-background-v1-draft.md)。

这是桌面内部实验，不是 MCP 服务或 Android/BIL 接入，不代表生产并发、系统 OOM、跨进程恢复、跨平台或性能验收。
