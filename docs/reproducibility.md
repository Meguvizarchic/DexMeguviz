# 可复现构建与候选核对

本说明用于准备本地工程候选；执行命令本身不意味着交付验收、设备运行、性能或公开发布已完成。项目源码及原始夹具的分发许可尚待所有者决定，Gradle 中的 `0.0.0-local-prototype` 和对应坐标仅用于本地验证，不代表正式版本或已确认的发布坐标。

## 固定输入

使用同一份冻结源码构建桌面与 Android 产物。将源码、头文件、构建脚本、启用功能的配置、第三方源码及锁文件逐项记录相对路径与 SHA-256；记录构建前后摘要并拒绝将发生变化的输入当作同一次构建。独立记录生成夹具及其生成器，保留原始命令、退出状态和构建日志。快照、输出与日志使用新的隔离目录，不覆盖已有记录；不要把本地配置、密钥、设备信息或敏感路径直接用于公开产物。

CMake 声明工程版本为 0.1.0，公共 C 头中的 `DMG_ABI_VERSION` 为 1；它们是当前源码声明，不代表正式兼容性承诺。桌面启用的可选功能以实际 CMake 选项和构建记录为准，SQL 默认关闭且仅支持桌面。第三方 miniz 3.1.2、可选 SQLite 3.54.1 的上游版本、归档与源码摘要及许可文件分别位于 `third_party/miniz/upstream-lock.json` 和 `third_party/sqlite/upstream-lock.json`，清单见 `THIRD_PARTY_NOTICES`。

Android 项目锁定 Gradle 9.8.2、Android Gradle Plugin 9.4.1、JDK 17、NDK 30.0.16248370、CMake 4.1.2、compile SDK 37.2、Build Tools 37.0.0；最低 API 27，目标 ABI 为 arm64-v8a 和 armeabi-v7a。wrapper 分发摘要位于 `bindings/android/gradle/wrapper/gradle-wrapper.properties`，Gradle 锁文件和本地 stdlib 摘要校验以源码为准。Kotlin 标准库 2.4.21 由宿主提供，库只作 compileOnly；构建时检查 release runtime classpath 和该编译依赖摘要。机器本地 SDK 配置和 Gradle 缓存不应替代源码记录或未经核实地进入分发包。

## 构建入口

桌面 Release 的 CMake 命令及显式可选目标见 `docs/getting-started.md`。Android 在 `bindings/android` 中使用 `gradlew.bat :dexmeguviz-android:assembleRelease --offline --no-daemon`；可选 sample 需显式 `-Pdmg.sample=true`。离线选项约束 Gradle 的依赖解析，不保证缺少 wrapper 分发时绝不尝试网络；请预先准备所需工具和依赖。依赖解析及校验失败时应保留错误并修正环境，不关闭锁定或摘要检查。

每次运行应记录实际工具版本、选项、输入摘要、构件摘要和完整可审阅日志。Windows 上如需设置短临时目录，应使用本轮新建目录并保留所需证据；测试只能清理本轮获准清理的自建临时文件。编译成功、静态审计、主机 JNI/R8 和设备/ART 是不同证据，不得相互替代。

## 本地候选与复核

候选应配套同源 AAR、对应桌面 CLI 与头文件、版本和 SHA-256 清单、依赖锁与许可说明、支持矩阵、构建及验证记录。仅在实际构建并复核后登记文件路径、大小、摘要、构建来源和启用选项；旧 AAR、旧 CLI 与后续源码不能混作同源候选。使用真实候选执行示例和文档命令，记录通过、失败或未执行及其环境，不将跳过计为通过。

`THIRD_PARTY_NOTICES` 记录第三方材料；项目许可及发布坐标未确定时应明确标记待定，不擅自对源码授予许可。构建时间、路径和平台工具可能影响字节，当前流程记录输入和产物摘要以供核对，尚未证明跨环境逐字节可重复。设备、BIL、完整性能比较及对外发布仍需要各自的实际证据和授权。
