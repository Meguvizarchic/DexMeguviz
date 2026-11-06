# Android 同源构建与主机验证运行器

入口为 `bindings/android/tools/run_same_source.py`。默认 `--mode plan`：只读取和散列源码、所选工具、编译器 manifest 及固定 suite，写入全新输出目录的 plan/summary，不复制源码，不配置、不构建、不运行测试。`plan.json` 的每一步都标记 `not_executed`；计划存在不等于通过。

```powershell
python -B bindings/android/tools/run_same_source.py `
  --root <LOCAL_PATH> `
  --jdk '<JDK17目录>' --sdk '<Android SDK目录>' `
  --gradle-cache '<已安装Gradle和依赖的缓存目录>' `
  --cmake '<支持本机VS的cmake.exe>' `
  --compiler-inputs '<固定Kotlin编译器路径及SHA清单.json>' `
  --out <LOCAL_PATH>
```

`--out` 必须不存在，且与源码及可选 `--overlay` 目录互不包含。Java 临时目录固定为新 out 下的 `t`，路径最多80字符。`--overlay` 仅用于审阅中的轻量源码候选：相同相对路径覆盖 root 的选择，所有来源路径和哈希都进入计划。不会复制已有 build/.gradle/.cxx、编译库、AAR、class、旧日志或其他已排除的产物；符号链接/目录 junction 不进入快照。选择规模限制为20000文件、512 MiB，不把整个工作区和历史证据复制到 D 盘。

## 构建与验证阶段

`--mode build` 在全新 out/source 中复制并复核选定源码，然后：

1. 用已安装的匹配 Gradle发行版构建 release AAR，执行现有无外部运行时依赖和宿主 stdlib校验，并记录实际解析的 compile/runtime/plugin artifact路径和哈希。同时只运行 `generatePomFileForLocalProbePublication` 和 `generateMetadataFileForLocalProbePublication` 生成同次构建的本地POM/module；不运行任何publish任务。
2. 单独保存 releaseRuntimeClasspath报告；生成的本地 SDK配置只写入隔离快照。
3. 从同一快照配置并构建 Windows JNI和现有 graph writer，禁用core测试、SQLite与fuzz；记录配置得到的主机compiler哈希。
4. 提取本次 AAR的 classes.jar，固定 AAR/classes/JNI/POM/module五项摘要，返回 `built_not_tested`，verify阶段全部列入 `not_executed`。POM/module仍是工程当前localProbe坐标，不冒充发行版本。

`--mode verify` 在它自己的全新 out 中完成上述构建，再依次调用当前 `verify_aar.py` 与类/keep注册、固定 Java/Kotlin主机消费者、既有 method/member binder runner 和 R8 runner。AAR审核同时传入本次POM/module与runtime报告，检查宿主提供Kotlin、无运行时传递依赖的约束。R8所需 jni-summary 只有前面的实际主机消费者和binder阶段全部成功、源码/工具未变时才产生；不会把旧receipt改个路径当本次通过。五项产物在执行前后再次核对。同源检查失败或任一步失败即停止，不替换失败记录、不重试、不发布。

可使用 `--approved-plan <计划.json>` 要求所选源码哈希、工具路径/哈希、固定 suite 和继承Java选项摘要与已审计划完全一致。输出目录与mode可以不同，工具移动、源码或环境选项变化则需生成新计划。`build`与`verify`各自使用新目录，当前不支持从任意旧构建或receipt恢复验证；希望只构建一次时，审核plan后直接运行一次verify。

## 已有入口及诚实覆盖

`android_suite_v1.json`列出六个现有Java消费者及四个现有Kotlin消费者的源码、main和精确fixture参数。类内容和Java/Kotlin/keep名单仍由当前 `verify_aar.py`、`jni_classfile.py`决定，不复制早期精确类集合。binder和R8继续保留既有断言。这里只建立可运行的统一编排，不为未覆盖的advanced/expand/precompute行为新增通过声明；完整公开接口、全部故障交错、实际Android/ART和BIL/Hook/UI仍另行验证。

工具参数包括 root/JDK/SDK/Gradle cache/CMake/compiler manifest/新out，并可显式覆盖 Gradle home、Android jar、R8 jar、readelf和suite。默认Gradle版本从工程wrapper配置读取，要求缓存中已经安装且唯一；直接启动已安装的CLI主jar，不运行可能下载发行版的wrapper。所有Gradle命令包含 `--offline --no-daemon`，保留依赖锁和验证元数据，不添加依赖，不执行clean、publish、install或设备任务。

## Java选项和日志

Gradle、Java和Kotlin使用JDK17。继承的 JAVA_TOOL_OPTIONS、_JAVA_OPTIONS、JDK_JAVA_OPTIONS 保持存在；runner给JAVA_TOOL_OPTIONS追加本次短临时目录。JAVA_OPTS和GRADLE_OPTS按Windows参数规则解析后原样传入Gradle的Java启动参数。后两者在可审argv中只显示占位符；各变量只记录是否存在及SHA-256，不保存真实值。

`launcher_log.py`在保存日志前遮盖Java启动器的上述三类环境选项banner。四个既有binder/R8入口采用同样遮盖；R8新增显式 `--preserve-java-options`，旧调用的默认清理环境选项行为不变，统一runner明确启用保留。现有输出保留策略没有改变，也没有增加删除动作。日志哈希针对实际保存的遮盖后内容。

单步日志32 MiB、单行1 MiB、单步默认1800秒。超限/到期会停止本runner创建的当前进程树；只使用该Popen的PID，不对已有系统或用户服务执行终止。输出全部保留，没有自动删除或清理。Gradle内部构建活动与缓存写入不是本工具的逐文件事务；所选输入、解析产物与最终构件有哈希记录，但不能据此宣称完全封闭或可复现构建。

## 固定排除和当前准备状态

运行器没有adb、设备、真实BIL、发布或coverage fuzz入口。先前被过滤的v5 fuzz及同等改名campaign、已拒旧CLI及为绕过拒绝的替身均不纳入计划。当前suite与复用入口不调用自动删除临时目录的旧CLI对照或历史fault runner。

准备阶段完成Python语法、日志遮盖及plan-only；随后按用户授权，从固定源码快照完成双ABI AAR、本地POM/module和Windows JNI构建。接续验证的17步通过：AAR/元数据审核、writer、六个Java和四个Kotlin现有消费者、method/member binder、R8 classfile/DEX及主机JNI。原构建收据和输入/产物前后摘要保持一致。

首次接续在JniJobTest失败，原因是suite把要求code-use-q03的第二参数误接成method-facts fixture；原断言未修改。最终suite只修正这一处为q03-domains.dex；已构建产物不重编，通过绑定原build plan及fixture SHA的显式override在全新目录重新验证，前次失败保留。其他消费者的fixture逐项读源码，并核对独立字节中的类/方法计数和字符串。

完整advanced/expand/precompute行为、所有故障/公开消费者、实际Android/ART/BIL和性能仍未因此通过；本页不提供设备、发布或删除授权。实际路径、摘要和原始日志由安装清单的validation/evidence引用。
