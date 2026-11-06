# 从源码使用DexMeguviz

工程仍在功能整合阶段；当前源码能力与早期保存的AAR不等同。先查看PROJECT_STATUS.json和相关合同，不将静态候选当运行时绑定或业务接受。

## 桌面

使用C++20工具链和CMake配置：

```text
cmake -S . -B build-local -DDMG_BUILD_TESTS=OFF -DDMG_BUILD_FUZZERS=OFF -DDMG_WITH_SQLITE=ON -DDMG_WITH_PERSISTENT_FACTS=ON -DDMG_BUILD_CORRESPONDENCE_TOOL=ON
cmake --build build-local --config Release --target dexmeguviz dexmeguviz_sql_session dexmeguviz_cache dexmeguviz_correspondence
```

这些桌面扩展默认关闭；开启SQL或持久缓存不把它们加入Android库。查询用法见cli和docs/contracts；预解算包入口为 `python tools/precompute/package.py --help`。缓存目录须由调用方控制并信任其写者，分片摘要不是认证。结构排序分数不是概率或最终接受。

## Android

构建入口为bindings/android，工具链与依赖版本以其中Gradle配置和锁定/校验文件为准。库仅提供compileOnly Kotlin标准库，宿主需自行提供已批准的2.4.21；不会将其嵌入AAR或声明传递运行时依赖。原生ABI为arm64-v8a和armeabi-v7a，minSdk27。Gradle当前要求JDK17。

```text
gradlew.bat :dexmeguviz-android:assembleRelease
gradlew.bat -Pdmg.sample=true :sample:assembleDebug
```

sample是可选Java宿主，使用自建DEX资产演示有序SourceSet和展开。示例Debug APK已在隔离快照构建；尚未安装或运行设备，构建命令不是运行时验收的声明。构建、安装和真实BIL切换分别是不同步骤。

`NativeEngine.openRawDexSet`返回可关闭的来源集合；同步/Job查询和结果值类型位于同包。Kotlin实体算子通过GraphExpression组合；单有界展开使用GraphExpression.expand、ExpandGraphQuery与ExpandExecution。多重/嵌套展开和部分profile组合尚未实现，明确拒绝。

```kotlin
val seed = GraphExpression.scan(EntityRelation.METHOD_DEFS,
    GraphPredicate.from(EntityPredicate.text(EntityTextField.OWNER,
        TextOperation.EXACT, "Lexample/Entry;")))
val relation = GraphExpression.expand(ExpandQuery(seed, maxDepth = 2, minDepth = 2))
val query = ExpandGraphQuery(GraphExpression.groupByOwner(listOf(relation)))
// snapshot由调用方持有并在使用结束时关闭；不因结果唯一就认为业务验收通过。
val result = ExpandExecution.execute(snapshot, query)
```

现有AAR、设备/ART、R8和完整ABI验收状态以项目证据为准。包消费和缓存命中仍需要读取、身份核对及必要运行时验真，不能声称零I/O或来源认证。

## 桌面SQL入口

SQLite构建可使用 `dexmeguviz sql base.apk --source split.apk --sql-file query.sql --params-file params.json --scope-incomplete`。驻留使用 `dexmeguviz_sql_session base.apk --source split.apk --scope-complete --sqlite-heap-mib 128`，随后按JSONL协议submit/run/final/ack/close，id必须使用返回的字符串。范围、参数标签和资源口径见docs/contracts/sql-cli-v1.md；不能用不同默认资源包络直接比较性能。

## 配套桌面命令

使用 `python -B tools/dexmeguviz.py --help` 查看native分派、保留日志的静态diff、有界metadata verify和预解算入口。支持范围及退出码见docs/contracts/desktop-commands-v1.md；该复核入口范围有限，不认证QueryID或运行时绑定。

## 桌面基准原始采集

benchmarks/desktop提供固定构件与语料的SQL一次性/驻留采集器。先按README预登记并预检，仅在独立正确性/生命周期门禁满足后正式采集；connectivity仅供自建小夹具连通，不产生性能接受结论，也不替代BIL A/B/C。
