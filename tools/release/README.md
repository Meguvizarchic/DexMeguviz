# 本地候选包生成与核对

`assemble_candidate.py` 将调用方显式指定并校验 SHA-256 的本地文件复制到全新输出目录；`verify_candidate.py` 只读核对输出中的文件集合、长度、SHA-256 和 `SHA256SUMS`。二者均使用Python标准库，不下载、不发布、不删除文件。输出明确标为 `local_unverified`：这些检查不认证构件来源或签名，不证明构件同源、项目许可、设备/ART、性能或发布验收。构建收据和已验证的实际源码身份须由调用方另行核对。

输入示例（每个sha256和source_build_id需由调用方替换为64位小写十六进制；path必须是现存绝对文件）：

```json
{"schema_version":1,"project_version":"0.1.0-local","artifacts":[{"kind":"android_aar","path":"D:/build/lib.aar","sha256":"...","source_build_id":"..."}]}
```

示例只展示字段，不是完整可执行清单。必需kind：`android_aar`、`desktop_cli`、`c_header`、`notices`、`miniz_license`、`miniz_lock`、`desktop_core_lib`、`desktop_miniz_lib`、`parameters_header`。可选 `sqlite_notice` 和 `sqlite_lock` 必须同时提供；含 `desktop_sql_session` 时必须提供SQLite这两项。可选 `persistent_header` 和 `desktop_cache_lib` 必须成对；另可提供 `desktop_cache_sources`、`bil_adapter`、`sample_apk`。固定输出路径以脚本中的映射表为准。项目license尚未确定，工具不会授予许可或选择正式发布坐标。

```text
python -B tools/release/assemble_candidate.py --input INPUT.json --out NEW_DIRECTORY
python -B tools/release/verify_candidate.py --directory NEW_DIRECTORY
```

输出目录必须不存在、父目录已经存在，所有输入需先通过类型/大小/摘要检查；失败保留已创建的部分目录供排查，不会覆盖已有目录。允许的单文件最大256 MiB、总计1 GiB；包含路径的原输入清单不会复制到输出。所有 `source_build_id` 只是调用方提供的哈希，不会认证来源或证明两份构件同源。启用SQL的其他构件是否需要额外许可，仍须由调用方按实际构建核对。

核验器拒绝未知文件、链接/junction、异常schema和摘要/大小不符；它不防御其他进程并发替换目录，不是文件系统沙箱。成功状态是 `integrity_verified_not_authenticated`，而不是发布通过。此功能只做过合成输入的有限连通，真实同源产物、文档示例与许可证/发布门禁仍待正式验收。

## DexKit 标记检查

`scan_dexkit_markers.py` 只读扫描指定 AAR 内全部类与原生库字节、嵌入 JAR 和同次构建的运行时依赖报告中的 DexKit ASCII/UTF-16 标记；输入、解压、路径与 ABI 均有限制。退出码 0 表示所检查表面无标记，1 表示发现标记，2 表示输入无效或不支持。可用 `--expected-aar-sha256`、`--expected-report-sha256` 锁定已知输入，按需重复 `--require-abi arm64-v8a` 等参数。工具不能证明混淆改名或外部动态加载不存在，也不认证报告与 AAR 的同源关系；还须独立核查消费者的直接/传递/测试依赖和实际 APK。
