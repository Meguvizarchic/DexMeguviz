# DexMeguviz API 与模块速查

## 1. 制品、目标与工具链基线

### 1.1 Android AAR 制品

| 项目 | 真实基线 |
| --- | --- |
| Maven Central 坐标 | `io.github.jichuo1.dexmeguviz:dexmeguviz-android:1.2.0` |
| BOM 管理 | `io.github.jichuo1.meguviz:meguviz-bom:1.2.0`（可省略 `1.2.0`） |
| Android 最低/编译 SDK | `minSdk 27`，应用需 `compileSdk 37.2` 或更高版本 |
| 工具链对齐 | Gradle `9.8.2`、AGP `9.4.1`、JDK `17`、Build Tools `37.0.0`、NDK `30.0.16248370`、CMake `4.1.2` |
| 原生 ABI 与产物 | `arm64-v8a`、`armeabi-v7a`，打包单个 `libdexmeguviz.so`（静态链接 `miniz` 与 `c++_static`） |
| Kotlin 标准库 | AAR 仅 `compileOnly("org.jetbrains.kotlin:kotlin-stdlib:2.4.21")`，**宿主必须自行提供** |
| 可选跨库桥接 | `io.github.jichuo1.meguviz.hook:hook-dex-bridge:1.2.0`（与 `MeguvizHook` 配合时按需引入） |

### 1.2 CMake 原生与桌面 Target

根 `CMakeLists.txt` 要求 CMake `3.25+` 与 C++20 工具链：

| CMake Target | 启用选项 | 类型与用途 |
| --- | --- | --- |
| `dexmeguviz_core` | 默认启用 | C++20 静态核心库（导出 C ABI `dmg_*`） |
| `dexmeguviz` | 默认启用 | 桌面 CLI（`inspect` / `query` / `explain`，启用 SQLite 时含 `sql`） |
| `dexmeguviz_android` | Android 构建启用 | 生成 `libdexmeguviz.so`（仅导出公开 `dmg_*` 与 JNI 入口） |
| `dmg_sqlite_method_tables`、`dmg_sqlite_resident`、`dexmeguviz_sql_session` | `-DDMG_WITH_SQLITE=ON` | 桌面私有 SQLite 虚拟表适配器与 JSONL 驻留查询进程（Android 禁用） |
| `dmg_persistent_facts`、`dexmeguviz_cache`、`dexmeguviz_cache_sources` | `-DDMG_WITH_PERSISTENT_FACTS=ON` | 桌面持久化 facts 缓存库与命令行工具（Android 默认关闭） |
| `dexmeguviz_correspondence` / `dexmeguviz_dataflow` / `dexmeguviz_041` | 对应 `-DDMG_BUILD_*_TOOL=ON` | 桌面结构排序、寄存器数据流及实验性 DEX 041 诊断工具 |

## 2. Android Java/Kotlin 核心 API（包 `io.github.jichuo1.dexmeguviz`）

### 2.1 来源打开与流式导出

| 类与方法 | 输入上限与关键特性 |
| --- | --- |
| `NativeEngine.openRawDex(bytes, slot)` / `openRawDexWithLimits(...)` | 单份原始 DEX 拷贝快照（默认最大 16 MiB），`slot` 为 1~128 字符可见 ASCII，必须关闭 |
| `NativeEngine.openRawDexSet(bytes, slots)` | 1~8 份有序原始 DEX，总计最大 16 MiB，`sourceScopeComplete` 为 `false` |
| `NativeEngine.openSources(bytes, slots, formats, allowNoDex)` | 1~8 个 `SOURCE_RAW_DEX` / `SOURCE_APK` 输入，展开 DEX 至多 64 个且总计 ≤ 16 MiB |
| `AndroidApkSources.plan(info, [declaration], baseAllowNoDex, splitAllowNoDex)` | 仅复制 `ApplicationInfo` 路径元数据，不自动发现或加载 |
| `AndroidApkSources.open(infoOrPlan, expectedSha256, limits)` | 最多 8 个 APK；由 `ApkFdLimits` 约束核心内存预算，必须在后台线程打开并关闭 |
| `AndroidApkSources.openBorrowed(pfds, offsets, lengths, slots, allowNoDex, sha256, limits)` | 借用调用方持有的 `ParcelFileDescriptor` 区间，同步拷贝后返回 |
| `NativeEngine.openMethodStream(queries, maxSourceBytes, maxOwnedBytes)` | 预编译方法规则，逐份打开并关闭原始 DEX 快照以控制内存峰值，支持 `queryMethodsBatch` |
| `DexStreamExport.writeTo` / `writeAll` | 将快照静态字节按块写入调用方 `OutputStream`（不负责创建、刷新或关闭流） |

### 2.2 查询构建、执行与异步 `Job`

| 场景 / Profile | 入口类与核心方法 | 注意事项 |
| --- | --- | --- |
| `method-v1` 方法查询 | `MethodQuery` + `QueryExecution.execute(snapshot, query)` | 需通过 `MethodPredicate` 构造条件，支持 `ENUMERATE` / `EXISTS` / `UNIQUE` |
| `method-batch-v1` 批量复用 | `MethodBatchQuery.execute(snapshot, rules, cacheBytes, maxCacheWork)` / `ScopedMethodBatchQuery.execute(...)` | 单规则失败导致整批失败；`Scoped*` 支持在查询 JSON 中声明局部 `slots` |
| `entity-v2` 七类实体 | `EntityQuery` + `QueryExecution.execute(snapshot, query)` | 覆盖 `METHOD_DEFS`、`CLASS_DEFS`、`FIELD_DEFS`、`METHOD_REFS`、`FIELD_REFS`、`TYPE_REFS`、`STRING_VALUES` |
| `relational-v3` / `v14` / `v17` 关系图 | `GraphExpression` + `GraphQuery` + `TypedGraphQueryExecution` / `GraphQueryExecution` | 支持 `scan`、`filter`、`label`、`union`、`distinct`、`join`、`semiJoin`、`groupByOwner` |
| `expand-v5` 有界展开 | `ExpandQuery` + `ExpandGraphQuery` + `ExpandExecution` | 仅支持单次 `GraphExpression.expand`，禁止嵌套/多重展开或与 `reflection` 混用 |
| `opcode-sequence-v23` | `OpcodeQuery.execute` / `startJob`，`ScopedOpcodeQuery.execute` | 指令序列四模式与可选计数；负数通配与 signed16 转换须在 JSON 中显式启用 |
| `class-annotation-static-v24` / `v25` | `ClassAnnotationQuery`、`ScopedClassAnnotationQuery`、`ClassAnnotationStringQuery`、`ScopedClassAnnotationStringQuery` | 顶层整数或字符串注解查询，保留 `UNKNOWN` 语义 |
| 选定方法深度检查 | `MethodFactsExecution.inspect`、`MethodParametersExecution.execute`、`AnnotationExecution.inspect`、`snapshot.inspectMethodCalls` | 针对单个选定本地方法，未实现方法体或无 debug 信息会返回明确状态 |
| 高级使用点与特定图 | `UseGraphQueryExecution`、`ScopedUseGraphQuery`、`TypeUseQuery`、`MethodTypeQuery`、`FieldDeclarationQuery`、`CallerFieldRelationQuery`、`ReflectionMethodUsesExecution` | 各版本独立门控，不支持跨版本任意组合能力位 |
| 极速与并行实验入口 | `FastDexQuery`、`ParallelDexQuery`、`ParallelFastDexQuery`、`NativeApkFastQuery` | 仅用于调用方已自行保证合法与有序 ID 表的受控 DEX，结果 `coverage` 恒为部分覆盖 |
| 异步流 `Job` | `QueryExecution.startMethodJob` / `startEntityJob`、`TypedGraphQueryExecution.startJob`、`ExpandExecution.startJob`、`OpcodeQuery.startJob` | 单消费者顺序调 `next(timeoutMs)`（`kind`: `0` 批次、`1` 超时、`2` EOS），EOS 后调 `status()` 或 `waitFor(timeoutMs)`；可并发调用 `cancel()` 与 `close()` |

### 2.3 运行时绑定与结果判定枚举

`Result.kt` 定义了独立于行数的判定维度：`ExecutionStatus`（`COMPLETE`、`INVALID_ARGUMENT`、`CORRUPT_INPUT`、`UNSUPPORTED`、`BUDGET_EXCEEDED`、`OUT_OF_MEMORY`、`INTERNAL_ERROR`、`CLOSED`、`SOURCE_MISMATCH`、`CANCELLED`、`DEADLINE_EXCEEDED`、`NOT_READY`、`END_OF_STREAM`）、`Coverage`（`COMPLETE`、`PARTIAL`）、`Decision`（`NOT_APPLICABLE`、`UNDETERMINED`、`PROVEN_FALSE`、`PROVEN_TRUE`）。

- `RuntimeMethodBinder.bind(loader, generation, candidate)` / `bindDescriptor(...)`：返回 `Status.BOUND`、`OWNER_NOT_FOUND`、`SIGNATURE_MISMATCH`、`INVOCATION_MISMATCH` 等，`origin` 始终为 `Origin.UNVERIFIED`。
- `RuntimeMemberBinder.bindField` / `bindConstructor` / `bindClass` / `bindOwnerAnchor`：按字段、构造器与宿主类做显式未缓存绑定。
- `MethodSourceObservation.query(opened, queryJson)`：将候选与 `ApkMetadataPlan` 的 slot、输入索引和摘要绑定，并通过 `Observation.bind(loader, generation)` 校验声明的 `loader` 与 `generation` 身份。

## 3. C ABI（`include/dexmeguviz/*.h`）与桌面 CLI

### 3.1 核心 C 头文件

- **`dexmeguviz.h`**（`DMG_ABI_VERSION = 1u`）：
  - 引擎与快照：`dmg_engine_create`、`dmg_engine_shutdown`、`dmg_engine_release`、`dmg_engine_get_stats`、`dmg_snapshot_open_copy_in`、`dmg_snapshot_open_borrowed`、`dmg_snapshot_open_fd`、`dmg_snapshot_open_sources`、`dmg_snapshot_open_apk_fds_v1`、`dmg_snapshot_open_dex041_copy_v1`（显式 DEX 041）。
  - 编译与执行：`dmg_query_compile_methods`、`dmg_query_compile_json`、`dmg_query_execute`、`dmg_multi_execute_v1`、`dmg_query_get_info_v2`、`dmg_query_get_explain_v1`。
  - 异步任务与局部事实：`dmg_job_start`、`dmg_job_next`、`dmg_job_wait`、`dmg_job_cancel`、`dmg_job_release`、`dmg_snapshot_collect_method_facts_v1`、`dmg_snapshot_collect_method_calls_v1`、`dmg_snapshot_collect_annotations_v1`、`dmg_snapshot_get_method_parameters_v1`（另见 `method_parameters_v1.h`）。
- **`fast_query_v1.h`**：`dmg_fast_compile_v1`（最多 16 条规则与 1 MiB JSON）、`dmg_fast_scan_v1`（受 `dmg_fast_limits_v1` 约束，不计入 `dmg_engine` 内存账本）。
- **`persistent_cache_v1.h`**：桌面端可选持久化缓存（链接 `dmg_persistent_facts`），提供 `dmg_persistent_cache_open_v1`、`dmg_persistent_cache_execute_v1`、`dmg_persistent_cache_close_v1`、`dmg_persistent_cache_get_stats_v1`。

### 3.2 桌面命令行与配套工具

- `dexmeguviz inspect INPUT [--source PATH ...] [--resource-source PATH ...] [--dex-checksums] --json`
- `dexmeguviz query INPUT --query QUERY.json [--source PATH ...] [--scope-incomplete] [--budget-mib N] --json`
- `dexmeguviz explain --query QUERY.json [--json]`（无输入 I/O）
- `dexmeguviz sql INPUT --sql-file FILE [--params-file FILE] [--sql-max-rows N] [--sql-identity-equality [--sql-identity-in]]`（需 `DMG_WITH_SQLITE=ON`）
- `dexmeguviz_sql_session INPUT [--source PATH ...] --sqlite-heap-mib N`（JSONL 驻留协议：`submit` / `run` / `final` / `ack` / `close`）
- `python -B tools/dexmeguviz.py`：桌面统一路由脚本（支持 `inspect`、`query`、`explain`、`sql`、`diff`、`verify`、`precompute`）。

## 4. 与家族兄弟库的协作边界

| 需求 | 推荐方案 | 边界说明 |
| --- | --- | --- |
| 端内静态扫描 + Hook 注入 | `DexMeguviz` + `hook-dex-bridge` + `MeguvizHook` | 可直接调用 `DexRefHookBridge.queryAndBindBatch`，或先扫描再经 `MeguvizRef` 验真后交给 `HookSpec` |
| 端内已有精准描述符，只需缓存反射/调用 | 转交 `MeguvizRef`（`meguviz-ref-core` / `meguviz-ref-android`） | `DexMeguviz` 的 `RuntimeMethodBinder` 不缓存反射句柄，也不管理 `CodeScope` 代次生命周期 |
| 桌面重型分析、MCP 服务、Smali/Manifest/资源表审计 | 转交 `MeguvizDexDash` | `DexMeguviz` 不提供 Smali 文本生成、ARSC 解析或 MCP Server |
