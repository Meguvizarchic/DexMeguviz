---
name: dexmeguviz
description: 用于在 Android 或 C++20/C ABI 项目中接入 DexMeguviz 静态 DEX/APK 查询，或将旧版 DexKit、手工 DEX 解析与零散反射扫描迁移为受控快照查询。触发场景包括端内 AAR 集成、MethodBatchQuery/OpcodeQuery/ClassAnnotationQuery 适配、多 DEX 有序扫描及 C ABI/桌面 SQLite 查询；若需桌面重型 Rust 引擎、MCP 协议或全量资源与 Manifest 审计，转交 MeguvizDexDash；若已有确定类签名只需运行期反射调用或安装 Hook，转交 MeguvizRef 或 MeguvizHook。
---

# DexMeguviz 接入与迁移

DexMeguviz 是面向 DEX（035/037/038/039/040）与 APK 的 C++20 静态查询引擎，提供 Android Java/Kotlin 绑定、稳定 C ABI（`dmg_*`）与桌面命令行/SQLite 入口。

## 第 1 阶段：盘点工程现状

修改代码前，先读取消费端配置并输出简短评估：

1. **选型分流核对**：
   - 需要 Android 端内嵌库（`dexmeguviz-android`）、C++20/C ABI 嵌入或轻量 CLI/SQLite 会话：继续使用 `DexMeguviz`。
   - 需要服务端/桌面重型 Rust 分析、MCP 工具服务、全量资源与 Manifest 审计或桌面工作台：转交 `MeguvizDexDash`。
   - 已有目标方法签名，只需运行期反射查找并复用调用计划：转交 `MeguvizRef`；需要安装方法拦截：转交 `MeguvizHook`。
2. **Android 工程基线**（查看 `build.gradle.kts` / `libs.versions.toml`）：
   - 确认 `minSdk >= 27`、`compileSdk >= 37.2`（对应 AGP `9.4.1`、Gradle `9.8.2`、JDK 17、NDK `30.0.16248370`），且应用配置已包含 `arm64-v8a` 或 `armeabi-v7a`。
   - **Kotlin 标准库规则**：`dexmeguviz-android` 以 `compileOnly` 依赖 `org.jetbrains.kotlin:kotlin-stdlib:2.4.21`，不会将其打包或传递。确认宿主自身显式引入了 `kotlin-stdlib:2.4.21`。
3. **存量查询与注入点盘点**：
   - 找出所有直接调用旧版 DexKit、全盘 APK 扫描、`Class.forName` 暴力试探或未设上限的 `ZipFile` 解压代码，记录输入来源（raw DEX、APK 路径或 PFD）和目标线程。
   - 若消费端为 C++ 工程，检查是否使用 C++20、CMake `3.25+` 以及桌面端是否需要 SQLite 虚拟表或持久缓存扩展。

## 第 2 阶段：选择模块与接入依赖

| 接入场景 | 选型坐标 / Target | 说明与边界 |
| --- | --- | --- |
| Android 端内接入 | `io.github.jichuo1.dexmeguviz:dexmeguviz-android:1.2.0` | 已发布至 Maven Central，并受 `io.github.jichuo1.meguviz:meguviz-bom:1.2.0` 管理 |
| 与 `MeguvizHook` 联合检索并绑定 | 额外加 `io.github.jichuo1.meguviz.hook:hook-dex-bridge:1.2.0` | 按需引入 `DexRefHookBridge.queryAndBindBatch`，不写 Hook 代码则不要引入 |
| 原生 C++20 / C ABI 嵌入 | CMake Target `dexmeguviz_core` | 头文件位于 `include/dexmeguviz/dexmeguviz.h` 等，按需链接 |
| 桌面命令行与可选 SQL/缓存 | Target `dexmeguviz`、`dexmeguviz_sql_session`、`dexmeguviz_cache` | SQLite（`-DDMG_WITH_SQLITE=ON`）与持久缓存（`-DDMG_WITH_PERSISTENT_FACTS=ON`）仅桌面可用，严禁带入 Android |

Gradle 接入示例（使用 BOM 对齐版本，并补齐宿主 Kotlin 标准库）：

```kotlin
dependencies {
    implementation(platform("io.github.jichuo1.meguviz:meguviz-bom:1.2.0"))
    implementation("io.github.jichuo1.dexmeguviz:dexmeguviz-android")
    implementation("org.jetbrains.kotlin:kotlin-stdlib:2.4.21")
}
```

C++20 / 桌面端通过 CMake 引入 `dexmeguviz_core`（默认关闭 SQLite 与持久缓存，桌面按需开启）：

```sh
cmake -S . -B build-local -DDMG_BUILD_TESTS=OFF -DDMG_BUILD_FUZZERS=OFF -DDMG_WITH_SQLITE=ON -DDMG_WITH_PERSISTENT_FACTS=ON
cmake --build build-local --config Release --target dexmeguviz dexmeguviz_sql_session
```

## 第 3 阶段：执行最小迁移与生命周期对齐

1. **在后台线程打开受限快照并及时关闭**：
   - 使用 `NativeEngine.openRawDexSet(bytes, slots)` 或 `AndroidApkSources.open(info, baseAllowNoDex, splitAllowNoDex, expectedSha256, limits)`，务必包裹在 `try-with-resources` 或 `.use { ... }` 中。
   - 不要在 UI 线程打开快照或执行同步查询；同步 `open` 不支持中途取消，如需限制内存峰值且逐份扫描 raw DEX，改用 `NativeEngine.openMethodStream`。
2. **用类型化查询或批量桥替换手写解析**：
   - 单规则方法检索：`MethodQuery` + `QueryExecution.execute(snapshot, query)`；多规则同源复用：`MethodBatchQuery.execute(...)` 或显式限定 slot 子范围的 `ScopedMethodBatchQuery.execute(...)`。
   - 其他专项查询：`EntityQuery`（七类实体）、`GraphExpression` + `ExpandQuery`（单层有界展开，禁止嵌套多个 `expand`）、`OpcodeQuery` / `ScopedOpcodeQuery`（v23）、`ClassAnnotationQuery` / `ScopedClassAnnotationQuery`（v24/v25）。
   - 异步可取消查询：`startMethodJob` 等返回的 `Job` 必须循环调用 `next(timeoutMs)` 直到返回 `kind == 2`（流结束）再查 `status()`，流未结束前的批次仅为临时结果；退出时可并发调 `cancel()` 与 `close()`。
3. **严格核对结果状态并完成运行时验真**：
   - 必须同时检查 `executionStatus == 0`（`COMPLETE`）、`coverage`（`0` 为完整，`1` 为部分）与 `decision`（`3` 为确认命中，`1` 为未确定，`2` 为确认未命中）。
   - **静态命中只是候选**：部分范围下的 0 候选不证明全局不存在；最终反射或 Hook 注入前，必须通过 `RuntimeMethodBinder` / `RuntimeMemberBinder`、`MethodSourceObservation.Observation.bind`、`MeguvizRef` 或 `DexRefHookBridge.queryAndBindBatch` 完成运行时验真。
4. **桌面 C++ / C ABI 与 SQLite 对齐要点**：
   - C ABI 通过 `dmg_engine_create` -> `dmg_snapshot_open_sources` / `dmg_snapshot_open_apk_fds_v1` -> `dmg_query_compile_json` -> `dmg_query_execute` 获取结果，并通过 `dmg_*_release` 成对释放。
   - 桌面命令行使用 `dexmeguviz inspect` / `sql` 或 JSONL 驻留进程 `dexmeguviz_sql_session`，并在查询结束时显式检查是否发生截断或预算超限。

```kotlin
val limits = ApkFdLimits(256L shl 20, 128L shl 20, 128L shl 20, 256L shl 20, 64L shl 20, 128L shl 20, 1000, 16L shl 20, 8L shl 20)
val query = MethodQuery(
    where = MethodPredicate.all(
        MethodPredicate.text(MethodTextField.OWNER, TextOperation.EXACT, "Lcom/example/Target;"),
        MethodPredicate.text(MethodTextField.NAME, TextOperation.EXACT, "targetMethod")
    ),
    intent = QueryIntent.ENUMERATE
)
AndroidApkSources.open(appInfo, false, splitAllowNoDex, null, limits).use { opened ->
    val result = QueryExecution.execute(opened.snapshot, query)
    if (result.executionStatus == 0 && result.candidateCount() > 0) {
        val candidate = result.candidate(0)
        val bound = RuntimeMethodBinder.bind(classLoader, loaderGen, candidate)
        if (bound.status == RuntimeMethodBinder.Status.BOUND) {
            // 仅使用已通过 ClassLoader 验真的 Method
        }
    }
}
```

异步 `Job` 消费须循环读取至 EOS 再判定终态：

```kotlin
QueryExecution.startMethodJob(snapshot, query, 64, 4, 5_000L).use { job ->
    while (true) {
        val poll = job.next(500)
        if (poll.kind == 2) break // END_OF_STREAM
        // kind == 0 时按需消费临时批次 poll.batch
    }
    val finalStatus = job.status()
    check(finalStatus.terminal && finalStatus.executionStatus == 0)
}
```

> **按需深入阅读**：完整 C ABI / Java / Kotlin 接口与参数表见 [API 与模块速查](references/api-and-modules.md)；存量 DexKit / 反射迁移对照、线程生命周期与排障清单见 [迁移对照与排障](references/migration-patterns.md)。

## 第 4 阶段：验证与交付清单

1. **消费方验证**：
   - Android 消费工程执行 release 或 debug 构建（如 `./gradlew :app:assembleDebug`），确认无 `kotlin-stdlib` 缺失或 `compileSdk` 版本冲突；在后台线程运行静态查询 + 运行时绑定测试，验证 `Snapshot` 与 `Job` 关闭后无句柄泄漏。
   - C++/CLI 消费工程验证 `ExecutionStatus` 与 `Coverage` 分支覆盖（含部分覆盖与预算超限场景）。
2. **本库源码自检**（修改或联调本仓库时参考）：
   - Android AAR 构建与无传递运行时依赖检查（在 `bindings/android` 下）：
     `./gradlew :dexmeguviz-android:assembleRelease :dexmeguviz-android:verifyNoExternalRuntime`
   - 桌面 CMake 构建与主机测试（仓库根目录）：
     `cmake -S . -B build-local -DDMG_BUILD_TESTS=ON -DDMG_WITH_SQLITE=ON`
     `cmake --build build-local --config Release --target dexmeguviz`
     `ctest --test-dir build-local -C Release --output-on-failure`
3. **回退检查**：若新查询预算不足或新 profile 暂不可用，确认已通过显式错误分支触发既有安全回退路径，禁止把 `PARTIAL` 当完整成功吞掉。
4. **交付摘要**：列出接入的坐标或 Target、改动的查询与绑定调用点、已执行的实际命令与通过范围，以及尚未在真机或全量语料验证的边界。
