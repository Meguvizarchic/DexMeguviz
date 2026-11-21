# 从源码使用 DexMeguviz

本指南介绍如何从源码构建并接入 DexMeguviz 桌面工具与 Android 库。

## 桌面构建

使用 C++20 工具链和 CMake `3.25+` 配置与构建：

```text
cmake -S . -B build-local -DDMG_BUILD_TESTS=OFF -DDMG_BUILD_FUZZERS=OFF -DDMG_WITH_SQLITE=ON -DDMG_WITH_PERSISTENT_FACTS=ON -DDMG_BUILD_CORRESPONDENCE_TOOL=ON
cmake --build build-local --config Release --target dexmeguviz dexmeguviz_sql_session dexmeguviz_cache dexmeguviz_correspondence
```

上述桌面扩展默认关闭；在桌面端开启 SQLite 或持久化缓存不会将它们带入 Android 构建产物。查询格式详见 `cli` 源码与 `docs/contracts/`；离线预解算打包入口可通过 `python tools/precompute/package.py --help` 查看。若启用持久化缓存，缓存目录及其写入权限须由调用方控制并信任。

## Android 构建与接入

Android 构建入口位于 `bindings/android`，工具链与依赖版本以其中的 Gradle 配置和锁定文件为准：

- 构建环境要求 Gradle `9.8.2`、AGP `9.4.1`、JDK `17`、NDK `30.0.16248370`、CMake `4.1.2`、`compileSdk 37.2` 与 Build Tools `37.0.0`。
- 目标运行基线为 `minSdk 27`，输出 ABI 为 `arm64-v8a` 与 `armeabi-v7a`。
- AAR 仅以 `compileOnly` 引用 `kotlin-stdlib:2.4.21`，不会嵌入该库或声明传递运行时依赖，宿主应用须自行提供已对齐的 Kotlin 标准库 `2.4.21`。

在 `bindings/android` 目录下运行以下构建命令：

```text
gradlew.bat :dexmeguviz-android:assembleRelease
gradlew.bat -Pdmg.sample=true :sample:assembleDebug
```

可选示例模块 `:sample` 为原生 Java 宿主，读取项目自建 DEX 资产演示有序 `SourceSet` 与图展开；详见 [示例应用说明](../bindings/android/sample/README.md) 与 [Android 构建切片](../bindings/android/README.md)。

`NativeEngine.openRawDexSet` 返回实现了 `AutoCloseable` 的来源集合快照；同步及 `Job` 异步查询入口均位于 `io.github.jichuo1.dexmeguviz` 包内。Kotlin 实体算子可通过 `GraphExpression` 组合，单层有界展开则使用 `GraphExpression.expand`、`ExpandGraphQuery` 与 `ExpandExecution`（多重/嵌套展开及部分不支持的 profile 组合会明确报错拒绝）：

```kotlin
val seed = GraphExpression.scan(
    EntityRelation.METHOD_DEFS,
    GraphPredicate.from(
        EntityPredicate.text(EntityTextField.OWNER, TextOperation.EXACT, "Lexample/Entry;")
    )
)
val relation = GraphExpression.expand(ExpandQuery(seed, maxDepth = 2, minDepth = 2))
val query = ExpandGraphQuery(GraphExpression.groupByOwner(listOf(relation)))
// snapshot 须由调用方持有并在使用结束后关闭
val result = ExpandExecution.execute(snapshot, query)
```

## 桌面 SQL 入口

在启用 `-DDMG_WITH_SQLITE=ON` 的构建中，可通过一次性命令行或 JSONL 驻留进程执行 SQLite 检索：

- **一次性查询**：`dexmeguviz sql base.apk --source split.apk --sql-file query.sql --params-file params.json --scope-incomplete`
- **驻留会话**：`dexmeguviz_sql_session base.apk --source split.apk --scope-complete --sqlite-heap-mib 128`，随后通过标准输入输出按 JSONL 协议发送 `submit` / `run` / `final` / `ack` / `close`（任务 `id` 须原样使用返回的字符串）。

作用域声明、参数类型标签及预算参数口径见 [SQL CLI 契约](contracts/sql-cli-v1.md)。比较一次性与驻留模式的性能时，须显式对齐两者的资源与内存预算包络。

## 配套桌面命令与基准采集

- 运行 `python -B tools/dexmeguviz.py --help` 可查看统一路由，涵盖原生命令分派（`inspect`、`query`、`explain`、`sql`）、保留扫描日志的静态差分（`diff`）、有界元数据独立核验（`verify`）与预解算工具（`precompute`）。具体子命令边界与退出码见 [配套桌面命令 v1](contracts/desktop-commands-v1.md)。
- `benchmarks/desktop` 提供面向固定语料的 SQL 一次性与驻留原始采集脚本；正式采集前需按对应说明完成预登记与连通性检查。

## 适用范围与验证说明

- 工程仍在功能整合阶段，当前源码新增能力与早期发布的 AAR 制品状态不完全等同，具体接口边界与已完成证据请先查阅 `PROJECT_STATUS.json` 与 [支持矩阵](support-matrix.md)。
- 静态查询返回的候选、结构排序分数、分片校验与缓存命中均只反映指定静态输入内的观测结果，不构成运行时 `ClassLoader` 绑定、来源签名认证或业务验收证明；最终注入或反射前须在目标运行环境中完成绑定校验。
- 示例构建成功、本地交叉链接或有限连通测试均各自独立于设备安装、ART 验证与真实业务场景验收。
