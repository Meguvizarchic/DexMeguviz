# 桌面 SQL 目录与二进制值扩展

状态：功能已接通的内部实验接口，仍由 `DMG_WITH_SQLITE` 显式启用；不进入 Android、JNI 或稳定公共 C ABI。既有十三个表的列顺序与值域保留，增加以下三个表。完整差分、资源压力与跨平台专项验证留待功能整合后执行。

## 逻辑 DEX 与使用点

`dmg_logical_dex(logical_dex_id TEXT, content_id TEXT, source_sha256 TEXT, dex_bytes INTEGER, dex_version INTEGER, occurrence_count INTEGER)` 每个当前数据集中不同的 `logical_dex_id` 一行。身份沿用核心逻辑 DEX 的域，同一内容作为多个来源出现时 `occurrence_count` 计数所有出现。`dmg_sources`、实体表及使用点表仍保留每个 occurrence，绝不因为该目录去重而合并它们。使用 `dmg_sources.logical_dex_id` 连接目录；目录 rowid 是当前首次出现顺序的零起始序号，只在本快照内有效。当前标准 DEX 的 header offset 是 0，未因此支持 DEX041 容器或运行时加载身份。

`dmg_type_uses` 的列与已有三个使用点表相同：`source_index, caller_ordinal, caller_reference_index, code_offset, dex_pc, opcode, target_domain, target_index, extra_proto`。它调用当前核心的 checked 类型使用事实收集器，覆盖 `const-class/check-cast/instance-of/new-instance/new-array/filled-new-array/filled-new-array-range`。`target_domain=5`，`target_index` 是同来源 type_id，`extra_proto` 为 NULL。可与 `dmg_type_refs` 按 source_index 和 reference_index 连接取得 descriptor。相同目标的不同 PC、不同方法或来源保留不同事件。完整扫描失败、取消和限额沿用其他使用点表的严格错误传播；不转为成功空表。预算、扫描 rowid 和 scope 声明仍沿用 sql-v1 的规则。

## 无损字符串字节与 BLOB

`dmg_string_data(source_index INTEGER, ordinal INTEGER, raw_mutf8 BLOB, utf16_length INTEGER)` 每个来源 string_id 一行；`raw_mutf8` 返回源 DEX 的原始 string_data payload，不包含前置 ULEB128 长度或末尾零终止符。它不从 UTF-16 重新编码，因此保留源字节；读取前重新核对偏移、范围与终止符，并受当前 SQLite 单值长度和取消检查约束。`utf16_length` 来自已检查元数据的 UTF-16 单元数量。空字符串对应非 NULL 的零字节 BLOB；未配对代理项可通过 BLOB 读取，原 `dmg_string_values.value` 的严格 Unicode 文本转换仍可拒绝它们。

内部 `SqlValue::Kind` 和 `SqlParameter::Kind` 在原 null/integer/text 后追加 blob；同一个 `text` 成员在 blob 标签下保存或借用未经字符转换的字节。TEXT/BLOB 的参数字节和输出字节都计入既有逻辑配额，NULL 与零字节 BLOB 分开。绑定使用 `SQLITE_TRANSIENT`；严格结果、provisional 回调、已提交分页、同步驻留与后台驻留队列均保留标签和字节，分页/队列按同一字节数计费。

两个驻留 JSONL 模式的 BLOB 采用 `{"blob_hex":"0001ff"}`。参数必须是一个且仅一个标签、偶数长度、小写十六进制；空串表示空 BLOB。返回值用同样的标签表示；原整数字符串、TEXT 和 NULL 格式不变。协议仍属于实验性 schema_version=1 的可选新值形态，旧客户端须显式识别新标签，不能把 BLOB 当文本。SQL REAL/浮点返回值仍明确拒绝。允许 BLOB 不增加函数白名单、写入权限或外部文件访问。

## 访问计划与验证边界

`xBestIndex` 将 SQLite 的 `colUsed` 以 `columns:<decimal mask>` 写入访问方案，`xFilter` 接收并验证，`xColumn` 只允许读取声明需要的列。原先的 identity 等值/IN opt-in 不变，residual、排序和 LIMIT 仍由 SQLite 负责。文本转换和原始字节读取均发生在所需列真正被访问时；这只接通了投影计划，不声明存在新的压缩行布局、解码列裁剪或性能收益。

本次仅完成 Windows Debug 桌面构建与五个同步驻留查询的基本连通检查：逻辑目录、原始字节、类型使用点连接、BLOB 参数和空 BLOB/NULL 区分、既有方法计数。没有执行全套 S01–S11、后台 BLOB 专项、游标 BLOB 压力、真实 OOM、重复来源目录差分、所有非规范字符串、ASan 或设备测试。未将 P3 任一任务标 done；SQLite/RSS 全内存账本、断线持久恢复、MCP、生产发布与全项目验收仍未完成。
