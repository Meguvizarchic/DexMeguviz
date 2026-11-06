# SQL 暂定行与终态（内部草稿）

`SqlSession::query_provisional_scoped_bound` 只用于 `open_scoped` 或 `open_scoped_planned` 的单线程会话。调用方显式提供 `SqlProvisionalSink`；SQLite 每成功生成并完整复制一个受支持的行后，同步调用 `on_row`，索引从 0 连续递增。回调收到的行与范围元数据仅在该次回调期间有效；调用方若保留必须自行复制。回调不得抛异常或重入同一会话，返回 0 表示继续，非 0 中止本次执行。

所有回调行均为 provisional。调用方必须检查调用返回码和 `SqlProvisionalOutcome`：只有 `terminal=true` 且 `execution_status=SQLITE_OK` 才表示整条语句执行、finalize 和最终取消检查均成功；任何其他终态都要求丢弃本次已观察行。`rows_emitted` 包括回调已看到但随后拒绝的行；它不是提交行数。输入无效、预算不足、取消、回调拒绝、类型不支持、SQLite 或内存失败都不能转为成功。会话或 sink 本身无效、或范围元数据在任何回调前无法分配时，调用直接失败且终态输出保持不变；此时没有行交付。

每个行回调与终态都携带同一复制的 snapshot ID、输入数、来源数和范围标签。范围仅是静态来源声明；即使终态成功，partial 来源下的聚合、排序、`COUNT` 或 `NOT EXISTS` 也不是全局结论。已有严格提交 `query_scoped_bound` 与 `query_cursor_scoped_bound` 语义不变。

`max_rows` 和 `max_bytes` 对本次所有生成行累计，按严格查询相同的每行/每列/TEXT 逻辑字节计费，不因回调逐行消费而重置。库不保留已交付行，但 SQLite 内存、单行临时对象、元数据、回调自行保留的副本及 RSS 不受该逻辑预算完整覆盖。回调拒绝返回 `SQLITE_ABORT`；取消返回 `SQLITE_INTERRUPT`；支持类型与原查询一致。profile 开启时 `rows_staged` 计已交付给回调的暂定行，只有终态成功才将这些行计入 `rows_committed`；它是逻辑确认数，不表示库替调用方存储或撤销外部副作用。

这是有界同步协议，不提供后台任务队列、磁盘 spool、重连恢复、公开 C ABI 或 Android 接口。测试范围仅固定 Windows DEX、同版本普通 SQLite 和定向失败样本；固定样本中已交付 provisional 行后，在 COUNT / NOT EXISTS 的 native 使用点收集器中取消或注入分配失败，验证失败终态和提交数为零，不能把注入失败等同于真实系统 OOM；回调的外部副作用无法自动回滚，完整 P3-03/P3-04 验收仍未完成。
