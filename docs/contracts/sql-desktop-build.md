# 实验性桌面 SQL 构建

SQLite 3.54.1 使用工程已固定源码及许可证，默认不编入核心或 Android。仅在桌面通过 `-DDMG_WITH_SQLITE=ON` 显式启用 `dmg_sqlite_method_tables` 和 `dexmeguviz_sql_session`；Android 显式启用会被拒绝。独立目标不改变默认 `dexmeguviz` CLI 或公开 C ABI。

主机验证可额外设置 `-DDMG_BUILD_SQLITE_PROTO_TESTS=ON` 并运行名称以 `sqlite_` 开头的 CTest；此选项启用测试专用故障钩子，不应作为普通构建。测试源码和合成 DEX 夹具位于 `tests/sql/` 及 `tests/fixtures/generated/`；标准测试不执行历史证据采集脚本，Python 优化模式拒绝检查只验证当前独立字节 oracle。

桌面 CLI 的 JSON Lines 协议见 [resident-cli-v1-draft.md](resident-cli-v1-draft.md)，表语义及资源限制见 [sql-v1.md](sql-v1.md)。当前是单线程、单 raw DEX、显式不完整范围的实验性实现，不代表生产 SQL、Android 运行、完整内存账本、跨进程恢复或任务全部验收。
