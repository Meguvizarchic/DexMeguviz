# 桌面 SQLite 单语句复用（内部草稿）

`SqlSession::enable_statement_reuse(max_statement_bytes)` 只允许在范围化会话中显式开启一次，单个会话最多保留一条已验证的只读语句；默认关闭。语句以完整 SQL 字节及 `max_bytes` 精确匹配，超限或不同 SQL 时不复用。相同参数数量在每次执行时重新验证与绑定；成功执行后清除所有绑定，因此前次参数不应泄漏到下一次。SQL 字节及 SQLite statement 在缓存存活期间留在进程内存；错误或关闭时清除逻辑键并销毁 statement，但不保证 C++ 字符串容量或 SQLite 释放内存被安全擦除。不要将该能力当作不含敏感 SQL 的持久缓存。

专用 `query_scoped_reused_bound` 与原有 `query_scoped_bound` 是不同入口。前者在语句完整 `SQLITE_DONE` 后检查 `sqlite3_reset` 与 `sqlite3_clear_bindings`、取消和内存估计，再提交复制的行与快照范围标签；未保留的语句仍须成功 `finalize`。任何已领取语句的绑定、执行、重置、清除、预算、取消或分配失败不会替换调用方结果，语句由局部所有权销毁。预校验或预取消发生在领取语句之前，已有缓存可保留。原严格入口继续逐次 `finalize`，不借用缓存。关闭会话时销毁保留语句。

开启后会话保持与原查询相同的只读 authorizer，避免每次重新安装 authorizer 使已准备语句过期；即使 SQLite 因 schema 或绑定值自动重新准备，authorizer 在 `step` 期间仍有效。`statement_reuse_stats` 分别报告本入口的显式 prepare 次数、缓存句柄命中和成功执行中观察到的自动 reprepare；缓存命中不保证执行计划未重新编译。启用 profile 时，缓存命中没有显式 prepare，`prepare_attempted` 和 `prepared` 为 false，首次 step 和执行终态仍按既有语义记录。

`max_statement_bytes` 比较 SQLite `SQLITE_STMTSTATUS_MEMUSED` 的近似保留大小，超过时查询仍可成功但不缓存；SQL 代码上限仍为 65,536 字节。此限额不覆盖 prepare/step 的临时内存、C++ SQL 字符串容量、SQLite 连接、结果、其他游标或 RSS；计数和耗时不代表全局资源账本。会话仍是单线程且禁止回调重入。此草稿只支持一槽、显式 opt-in、内存中同一快照和范围化结果，不代表完整 P3-04、驻留索引复用、并发或生产 SQL。

SQLite 的 [reset](https://www.sqlite.org/c3ref/reset.html)、[clear bindings](https://www.sqlite.org/c3ref/clear_bindings.html)、[authorizer](https://www.sqlite.org/c3ref/set_authorizer.html) 和 [statement status](https://www.sqlite.org/c3ref/c_stmtstatus_counter.html) 契约是该隔离实现的依据；具体测试只证明其记录的固定主机范围。

`clear_statement_reuse_cache()` 显式销毁当前缓存并清除逻辑键，使会话可在不关闭连接或丢弃快照的情况下释放该语句；空缓存时成功。配置和累计计数保持，后续相同查询重新 prepare；SQLite finalize 错误会返回，缓存始终不再持有该语句。该操作同样不承诺内存安全擦除。
