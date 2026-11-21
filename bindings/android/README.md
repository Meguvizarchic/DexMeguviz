# DexMeguviz Android 绑定

本模块提供 `dexmeguviz-android` AAR 的源码构建与原生绑定说明，包含 JNI 接口、Java/Kotlin 封装以及显式 APK 来源支持。

## 能力与核心接口

- `NativeEngine` 提供 ABI 与能力探测，以及显式传入的有序 raw DEX / APK 复制式快照。APK 内的多个 DEX 按数字顺序展开，并支持显式标记无 DEX 的资源 split 包；所有快照均需在使用结束后关闭。
- 同步与异步查询：支持 `method-v1` 同步查询、受限异步 `Job` 流（批次在流结束前均为临时结果，须顺序读取至 EOS 并检查终态）、七类直接实体查询（`entity-v2`）以及限定范围内的 `v3` / `v14` 元数据关系图查询。`capabilities()` 返回核心引擎的能力声明，不代表这些能力均已接入 JNI。
- 有关各接口的精确边界，详见 [原始来源契约](../../docs/contracts/android-jni-raw-source-v1.md)、[来源集合契约](../../docs/contracts/jni-source-set-v1.md)、[方法查询契约](../../docs/contracts/jni-method-query-v1.md)、[方法异步 Job 契约](../../docs/contracts/jni-job-method-v1.md)、[实体查询契约](../../docs/contracts/jni-entity-query-v1.md)、[关系图查询契约](../../docs/contracts/jni-graph-query-v1.md) 与 [Kotlin 查询契约](../../docs/contracts/kotlin-query-v1.md)。

## 构建参数与离线编译

当前固定构建配置如下：

- **构建工具链**：Gradle `9.8.2`、AGP `9.4.1`、JDK `17`、NDK `30.0.16248370`、CMake `4.1.2`、Build Tools `37.0.0`
- **Android 规格**：`compileSdk 37.2`、`minSdk 27`、输出 ABI `arm64-v8a` 与 `armeabi-v7a`
- **Kotlin 标准库**：模块启用 Kotlin `2.4.21`，但仅以 `compileOnly` 引入标准库，不打包进 AAR 也不声明传递运行时依赖，须由宿主应用自行提供；`verifyNoExternalRuntime` 任务会校检 `releaseRuntimeClasspath` 为空
- **原生链接**：核心静态链接已批准的 `miniz` 与 NDK `c++_static`，默认关闭 SQLite；最终生成单个 `libdexmeguviz.so`，通过版本脚本仅导出公开 `dmg_*` 与 JNI 入口

在具备对应工具链与本地依赖缓存的环境中，可执行：

```text
gradlew :dexmeguviz-android:assembleRelease :dexmeguviz-android:verifyNoExternalRuntime --offline
```

注意事项：若离线缓存中尚无指定的 Gradle 分发包，wrapper 仍可能尝试网络拉取；wrapper JAR 与 distribution 的 SHA-256 固定为 Gradle `9.8.2` 官方发布值，`local.properties` 仅作本机配置，不纳入版本库。

## 显式 APK 来源与预算控制

`AndroidApkSources.plan` 仅复制调用方提供的 `ApplicationInfo` 元数据；`open(plan, expectedSha256, limits)` 须在后台线程同步读取指定 APK 并返回待关闭的快照（旧 `open(ApplicationInfo, ...)` 会在调用时现场生成计划并打开）。`openBorrowed` 接受调用方持有的 `ParcelFileDescriptor`（PFD），同步返回前调用方须保持文件描述符有效且内容不变。上述入口均不自动发现安装包或 `ClassLoader`。

[ApkPlanExample.java](examples/ApkPlanExample.java) 演示了在调用方自备 `ExecutorService` 上打开计划、检查部分覆盖（`incomplete coverage`）并用 `try-with-resources` 关闭快照的写法。注意同步打开过程不支持中途取消（取消 `Future` 或中断线程不保证立刻停止底层读取）。`expectedSha256` 可为 `null`；若传入，须按 base 与各 split 顺序提供 64 位小写十六进制摘要（单槽可为 `null`），仅用于核对已读副本而非签名或来源认证。

`ApkFdLimits` 的构造参数应由宿主按输入大小与设备内存评估配置，不代表进程总 RSS 上限。参数顺序依次为：owned 上限、单来源上限、单 APK 上限、全部 APK 上限、单 DEX 上限、全部 DEX 上限、目录条目数、中央目录字节数、所有条目名称字节数。示例如下（数值仅用于演示参数顺序）：

```java
long mib = 1024L * 1024;
ApkFdLimits limits = new ApkFdLimits(
    256 * mib, 128 * mib, 128 * mib, 256 * mib,
    64 * mib, 128 * mib, 1000, 16 * mib, 8 * mib
);
// boolean[] splitAllowNoDex 须与 info.splitNames 一一对应
Future<ApkPlanExample.Report> pending = ApkPlanExample.submit(
    backgroundExecutor, info, false, splitAllowNoDex, null, limits
);
```

APK 文件入口最多支持 `8` 个输入（旧 `openSources(byte[][], ...)` 的 `8` 输入与 `16 MiB` 限制维持不变）。允许资源包 `allowNoDex = true` 不表示容忍缺失或损坏文件。使用 `EXISTS` 意图时，`decision == 3` 表示在给定静态输入中观察到至少一个匹配；在部分覆盖下，无命中返回 `decision == 1`（未确定），调用方不得将部分范围的零候选推断为全局不存在。详见 [Android APK FD 来源草案](../../docs/contracts/android-apk-fd-sources-v1-draft.md)。

## 方法来源观察与显式绑定

`MethodSourceObservation.query(opened, queryJson)` 在同一个已打开的 APK 快照上执行 `method-v1` 查询（查询须投影 `owner`、`name` 与 `prototype`），返回结果除包含每个候选所属的 APK/DEX 摘要与 slot 外，还完整保留原始 `executionStatus`、`coverage`、`decision`、`reason` 与 `Unknown` 计数：

- `allInputMethodsScanned == true` 仅说明本次遍历既定输入时无 `Unknown` 且未触及结果上限，不代表应用或 `ClassLoader` 来源完整；使用 `EXISTS`、`UNIQUE` 或带限制的查询仍可能提前返回代表性候选。
- 需要运行时绑定时，计划须预先声明调用方自身的 `loader` 与 `generation` 对象；逐候选调用 `bind(loader, generation)` 会核对两者身份，返回的绑定结果始终标记为 `Origin.UNVERIFIED`。绑定过程可能触发对应加载器的类加载代码，但不会主动初始化目标类、调用目标或修改成员可访问性。详见 [方法来源观察草案](../../docs/contracts/method-source-observation-v1-draft.md)。

## 适用范围与验证说明

- AAR 目前未包含 Prefab 原生头文件，也未承诺对外提供稳定的 C++ 二进制 ABI；现有包名与接口边界应以仓库当前版本和契约文档为准。
- 主机 JVM 的 JNI 调用测试、ELF `16 KiB` LOAD 对齐检查以及 SDK 编译通过均不等于真实 Android 设备的 ZIP 对齐、ART 装载或完整性能验收；真实设备装载、PFD、动态来源与业务接入需另行验证。
