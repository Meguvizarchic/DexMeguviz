# Android 构建切片

这是 Android 打包与有限 JNI 来源的早期切片，不是完整 Kotlin SDK 或 Android 来源绑定。
`NativeEngine` 提供 ABI、能力探针，以及显式提供的有序 raw DEX / APK 复制式快照；该来源范围明确标为不完整，快照必须关闭。APK内多个DEX按数字顺序展开，允许显式标记资源包无DEX。提供同步 method-v1 查询并复制候选值，但不包含独立见证；自动来源发现和 Android 设备验证尚未实现；运行时方法、字段和构造器可显式绑定，但来源真实性不经认证，见 `../../docs/contracts/android-jni-raw-source-v1.md`、`../../docs/contracts/jni-source-set-v1.md` 和 `../../docs/contracts/jni-method-query-v1.md`。

快照还可启动受限 method-v1 异步 Job；批次为 provisional，必须顺序读取到流结束并检查终态，详见 `../../docs/contracts/jni-job-method-v1.md`。七类直接实体查询支持同步复制式 JNI 结果和 Kotlin 类型化调用，范围见 `../../docs/contracts/jni-entity-query-v1.md`；直接实体也支持受限异步 Job；限定 v3/v14 metadata 关系图可同步查询或使用有界 Job，并复制见证，见 `../../docs/contracts/jni-graph-query-v1.md`。`capabilities()` 报告核心能力，并不代表这些能力都已接入 JNI。

构建参数固定为 Gradle 9.8.2、Android Gradle Plugin 9.4.1、JDK 17、NDK 30.0.16248370、CMake 4.1.2、compile SDK 37.2、Build Tools 37.0.0、minSdk 27，输出 arm64-v8a 和 armeabi-v7a。
模块启用 Kotlin 2.4.21，标准库仅用于编译并由宿主自行提供，不打包或声明运行时传递依赖；`verifyNoExternalRuntime` 会检查 release runtime classpath 是否为空。Kotlin 查询支持使用显式快照调用有限 JNI method-v1；无快照入口仍不支持，范围见 `../../docs/contracts/kotlin-query-v1.md`。核心静态链接已批准的 miniz 与 Android NDK 的静态 C++ runtime，SQLite 不启用。

在具备已安装工具与本地依赖的环境，可执行：

```text
gradlew :dexmeguviz-android:assembleRelease :dexmeguviz-android:verifyNoExternalRuntime --offline
```

本次验证使用隔离的 SDK、Gradle 用户目录和临时目录。`--offline` 约束 Gradle 依赖解析；wrapper 若缺少指定 Gradle 分发仍可能先尝试下载，因此离线环境需要预先配置分发。wrapper jar 与 distribution SHA-256 固定为 Gradle 官方 9.8.2 发布值。`local.properties` 是机器本地配置，不纳入源码。

构建产生单个 `libdexmeguviz.so`，版本脚本仅导出公开 `dmg_*` 与 JNI 入口；内部 C++ 符号不作为接口。仓库暂未在 AAR 中提供 Prefab/native headers，也未承诺稳定 Android ABI。包名是工程计划中的暂定命名，未验证发布归属。

ELF 的 16 KiB LOAD 对齐及本地交叉链接检查不等于最终 APK 的 ZIP 对齐、设备装载或运行验证。主机 JVM 的 JNI 调用、异常与关闭已有定向测试；Android 装载、动态来源、Kotlin API、绑定和 BIL 集成均须另行验收。





## 显式 APK 文件与示例

`AndroidApkSources.plan` 只复制调用方提供的 `ApplicationInfo` 元数据；`open(plan, expectedSha256, limits)` 在后台线程同步读取计划指定的 APK 并返回必须关闭的快照。旧 `open(ApplicationInfo, ...)` 在调用时生成计划并打开；两者都不自动发现应用或 loader。计划不固定文件内容，也不证明来源，内容须在调用期间保持稳定。`openBorrowed` 接受调用方持有的 PFD，调用前后均由调用方管理，且在同步返回前不可关闭。

[ApkPlanExample.java](examples/ApkPlanExample.java) 使用调用方提供的后台 `ExecutorService`，明确传入 base 和每个 split 的 `allowNoDex` 及 `ApkFdLimits`，捕获计划后在工作线程打开并查询是否观察到至少一个方法定义，检查 incomplete coverage，使用 try-with-resources 关闭快照。宿主应在非 UI 线程消费 Future，管理并关闭自己的 executor；同步打开不支持取消，取消 Future 或中断线程不保证停止打开。`expectedSha256` 可以为 null；提供时按 base、split 顺序传入可信的 64 位小写十六进制摘要，单项可为 null。摘要只绑定读取副本，不是 APK 签名或 loader 身份认证。

预算须由宿主按实际输入与设备内存选择，不能视作总 RSS 上限。构造参数依次为：owned、单来源、单 APK、全部 APK、单 DEX、全部 DEX 字节上限、目录条目数、中央目录字节数、所有条目名称字节数。例如下面仅为说明参数顺序，不适用于所有应用：

```java
long mib = 1024L * 1024;
ApkFdLimits limits = new ApkFdLimits(
    256*mib, 128*mib, 128*mib, 256*mib,
    64*mib, 128*mib, 1000, 16*mib, 8*mib);
// boolean[] splitAllowNoDex 必须与 info.splitNames 一一对应，由调用方逐项决定。
Future<ApkPlanExample.Report> pending = ApkPlanExample.submit(
    backgroundExecutor, info, false, splitAllowNoDex, null, limits);
```

显式新入口至多8个 APK；旧 `openSources(byte[][], ...)` 的8输入和16 MiB限制不变。允许无 DEX 不等于容忍缺失或损坏的文件。该示例使用 EXISTS：`decision == 3` 表示在这些静态来源中观察到至少一个方法定义；当没有观察到方法时，incomplete coverage 下 `decision == 1` 为未确定，不能推断完整应用不存在方法。返回结果携带原始 status、coverage 和 decision，调用方不得将部分范围的零候选当作否定证明。详见 `../../docs/contracts/android-apk-fd-sources-v1-draft.md`。Android 设备、PFD 和 ART 运行尚未验证；Windows 主机及 SDK 编译不能代替设备运行。

## 方法来源观察与显式绑定

`MethodSourceObservation.query(opened, queryJson)` 使用同一已打开 APK 快照执行 method-v1 查询，核对计划、输入、DEX 条目和逐候选来源字段。查询必须投影 owner、name 和 prototype；得到的 APK/DEX 摘要与 slot 是本次静态观察，结果同时保留原始 status、coverage、decision、reason 和 Unknown 计数。

`allInputMethodsScanned` 只表示本次输入的方法已无 Unknown、无结果上限且遍历结束，不表示应用或 ClassLoader 来源完整；即使遍历完成，EXISTS、UNIQUE、TopN 等意图仍可能只返回代表性候选，不能据此声称候选列表完整。Android 快照的 `sourceScopeComplete` 仍为 false。早停、Unknown、结果上限时，已观察候选明确带 `inputScanIncomplete`，不能由候选数量推断唯一或缺失。

需要绑定时，计划须事先声明 caller 自己的 loader 与 generation 对象；逐候选调用 `bind(loader, generation)` 会核对两者对象身份，返回的 binder 结果始终 `Origin.UNVERIFIED`。加载器代码仍可能执行；桥不初始化、调用目标或更改成员可访问性。它不认证签名/loader来源，不取代逐归档上限、旧引擎业务选择或设备验收。详见 `../../docs/contracts/method-source-observation-v1-draft.md`。
