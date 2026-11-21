# DexMeguviz 迁移对照与排障

## 1. 存量模式向 DexMeguviz 迁移对照

### 1.1 旧版 DexKit / 无界遍历 -> `MethodQuery` + `MethodBatchQuery`

旧代码常见问题：直接将整个 APK 路径交给非受控原生扫描器、一次创建长期全局持有、或在未检查搜索范围完整性时直接假设结果唯一。

迁移做法：
- 使用 `AndroidApkSources.open`（配合 `ApkFdLimits`）或 `NativeEngine.openRawDexSet` 打开**受限的显式快照**。
- 将多组查找条件编排为 JSON 或使用 `MethodQuery` / `EntityQuery` / `GraphQuery`；若有多条方法检索规则针对同一批 DEX，使用 `MethodBatchQuery.execute`（或带显式 slot 子范围的 `ScopedMethodBatchQuery.execute`）减少重复遍历。
- 完成后立刻退出 `use` / `try-with-resources` 块关闭快照。

```kotlin
// 迁移前（典型反模式）：全局长期持有扫描器，且直接把空列表当成"不存在"
// val list = dexKitBridge.findMethod { ... }
// if (list.isEmpty()) return null

// 迁移后：后台打开受限快照 + 批量执行 + 检查状态与完整性 + 及时释放
val rules = arrayOf(
    query1.toQueryIrJson().toByteArray(Charsets.UTF_8),
    query2.toQueryIrJson().toByteArray(Charsets.UTF_8)
)
AndroidApkSources.open(appInfo, false, splitAllowNoDex, null, limits).use { opened ->
    val batch = MethodBatchQuery.execute(opened.snapshot, rules, 8L shl 20, 10_000_000L)
    for (i in 0 until batch.size()) {
        val res = batch.get(i)
        if (res.executionStatus != 0) {
            // 触发预算超限、不支持或损坏输入时的显式回退分支
            continue
        }
        if (res.coverage == 1 && res.candidateCount() == 0) {
            // 部分覆盖下零候选代表"未确定"，不能推断目标不存在
        }
    }
}
```

### 1.2 手工 `ZipFile` + `DexFile` / 暴力反射 -> `MethodSourceObservation` + 运行时验真

旧代码常见问题：通过 `Class.forName` 遍历包名、或手工读 `classes.dex` 字节后直接拼装反射。

迁移做法：
- 使用 `AndroidApkSources.plan(info, LoaderDeclaration(classLoader, generation), false, splitAllowNoDex)` 先记录预期加载器与代次标识，再由 `AndroidApkSources.open(plan, expectedSha256, limits)` 打开快照。
- 通过 `MethodSourceObservation.query(opened, queryJson)` 获取带来源 `sourceSlot`、`occurrenceId` 与 `archiveEntryName` 的候选列表。
- 对静态命中候选逐一调用 `observation.bind(classLoader, generation)`，或将描述符交给 `MeguvizRef` 的 `CodeScope` 进行解析与生命周期管理。
- 若目标用于 `MeguvizHook`，优先使用 `io.github.jichuo1.meguviz.hook:hook-dex-bridge:1.2.0` 提供的 `DexRefHookBridge.queryAndBindBatch`。

### 1.3 异步长耗时检索 -> 可取消的 `Job` 流

旧代码常见问题：在子线程执行不可中断的同步扫描，导致页面退出或超期后线程长期滞留。

迁移做法：
- 改用 `QueryExecution.startMethodJob(snapshot, query, batchSize, maxQueuedBatches, deadlineAfterMs)` 等异步接口（对应 C ABI `dmg_job_start`）。
- 单一消费者线程循环调用 `job.next(timeoutMs)`：
  - `kind == 0`：读取临时批次 `poll.batch`；
  - `kind == 1`：等待超时（超时本身不会取消任务，可决定继续等待或主动调用 `job.cancel()`）；
  - `kind == 2`：流已结束（EOS），随后必须调用 `job.status()` 或 `job.waitFor(...)` 检查 `terminal == true` 且 `executionStatus == 0` 才能确认结果有效。
- 宿主退出或任务取消时可从任意线程调用 `job.cancel()` 与 `job.close()`。

## 2. 生命周期、线程与所有权铁律

1. **禁止 UI 线程 I/O 与同步查询**：`openRawDexSet`、`AndroidApkSources.open`、`execute` 等均为同步阻塞操作，必须在后台线程或专用线程池执行。
2. **快照按实例串行、按时关闭**：Java 包装类对同一个 `Snapshot` / `SourceSetSnapshot` 实例内部已做 `synchronized(snapshot)` 串行保护，用完即关闭，避免持有多份大体积复制字节。
3. **C ABI 内存归属清晰**：
   - `dmg_snapshot_open_copy` / `dmg_snapshot_open_copy_in` 在返回前拷贝全部输入；
   - `dmg_snapshot_open_borrowed` 要求调用方保证 `dmg_buffer_lease` 提供的 `retain`/`release` 回调线程安全且底层字节绝对不可变；
   - 通过 `dmg_result_get_method`、`dmg_result_get_entity` 等拿到的 `uint16_t*` / `char*` 均为借用视图，仅在所属 `dmg_result` 或 `dmg_batch` 未被 `release` 前有效，且**不可对这些指针调用 `free`**。
4. **C++ MSVC 运行时兼容性**：桌面消费方若链接 `dexmeguviz_core` 静态库（或使用 `dmg_sqlite_method_tables`），需与核心一致使用 `_ITERATOR_DEBUG_LEVEL=0`（根 `CMakeLists.txt` 已通过 `PUBLIC` 传播给直接链接 `dexmeguviz_core` 的 CMake Target）。

## 3. 高频错误排查表

| 现象 / 报错 | 常见原因 | 解决方案 |
| --- | --- | --- |
| 运行期报 `NoClassDefFoundError: kotlin/...` | 消费工程未显式提供 `kotlin-stdlib:2.4.21` | AAR 仅 `compileOnly` 依赖 Kotlin 标准库，在宿主 `dependencies` 显式引入 `org.jetbrains.kotlin:kotlin-stdlib:2.4.21` |
| Gradle 解析或合并 manifest 报错 `compileSdk` 不足 | AAR 编译基于 Android SDK `37.2`、`minSdk 27` | 将宿主 `compileSdk` 升至 `37.2` 及以上、`minSdk` 设为 `27+`、配置匹配 ABI（`arm64-v8a` / `armeabi-v7a`） |
| `query` 返回 `executionStatus = 3`（`UNSUPPORTED`） | 使用了当前入口未支持的 profile、嵌套了多个 `expand`、混用了不被接受的 capability、或在安卓端调了 SQL | 核对 [支持矩阵](../../../../docs/support-matrix.md) 的对应入口与合法 JSON 结构；单层展开只用一次 `GraphExpression.expand` |
| `query` 返回 `executionStatus = 4`（`BUDGET_EXCEEDED`） | 超出 `max_work`、`max_results`、`ApkFdLimits` 或单输入 `16 MiB` 限制 | 在合理范围内上调 `maxWork` / `ApkFdLimits` 预算，或通过 `Scoped*` 接口缩小扫描 slot 范围，并保留降级路径 |
| `Job` 读取到 `kind == 2` 但 `executionStatus != 0` | 收到 EOS 不代表成功，任务可能在末尾因超时、取消或输入损坏而终止 | 流结束后必须检查 `job.status().executionStatus`、`coverage` 与 `errorMessage`，非 `0` 时丢弃先前临时批次 |
| `RuntimeMethodBinder` 返回 `OWNER_NOT_FOUND` 或 `SIGNATURE_MISMATCH` | 目标类在当前 `ClassLoader` 不可见，或运行期方法被混淆/裁剪与静态 DEX 不一致 | 核对传入的 `ClassLoader`（App vs 系统）、检查 R8 混淆规则，并按该状态走安全降级 |

## 4. 安全回退方案

1. **查询降级路径**：当静态查询返回 `BUDGET_EXCEEDED`、`DEADLINE_EXCEEDED`、`CANCELLED`、`CORRUPT_INPUT` 或 `UNSUPPORTED` 时，业务方应通过显式错误处理分支回退到既有确定性配置、精确已知签名调用（`MeguvizRef`）或安全跳过对应功能点，禁止将不完整结果视作“目标不存在”。
2. **版本与能力回退**：若宿主需要临时关闭某条新 profile 规则（例如 v23/v24/v25 扩展规则），可通过配置开关切回基础 `method-v1` 精确签名查询或已有静态配置；切勿静默降级为无界全包反射。
