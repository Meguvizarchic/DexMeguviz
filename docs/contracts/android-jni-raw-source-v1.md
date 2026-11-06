# JNI 原始 DEX 来源草稿

`openRawDex` 提供单个 raw DEX 的复制式静态快照；另有显式 raw DEX/APK 来源集合、限定同步方法/实体/v3 和 v14 metadata 关系图查询，以及 method-v1、直接实体与限定 v3/v14 metadata 图 Job。APK/base/split 自动发现、跨调用查询句柄、完整关系图 JNI、ClassLoader、binder、ART 验证和 BIL 尚未完成，P2-03 及其前置的完整验收仍未结束。

`openRawDexWithLimits(bytes, slot, maxSourceBytes, maxOwnedBytes)` 是显式限额变体：来源限额为 1 至 `Integer.MAX_VALUE` 字节，核心 owned 内存限额须为正数；超出任一限额会失败，旧入口的 16 MiB 限额不变。Java 数组、VM 和其他进程开销不计入核心内存限额，调用方须按设备能力设置；同步、不可取消及不完整来源范围与旧入口相同。

现有 `capabilities()` 仍返回底层 C 核心的能力字符串，不能据此推断所有核心查询接口已接入 Java/JNI；同步接口范围见 `jni-method-query-v1.md` 和 `jni-entity-query-v1.md`。

## 来源与边界

`NativeEngine.openRawDex(bytes, slot)` 同步复制不超过16 MiB的输入，调用方必须在返回前保持数组不变。输入准备不可取消；Java 数组和 VM 自身的内存不纳入核心 Engine 的内存预算。slot 为1–128个可打印ASCII字符、不含空格；namespace 固定为 `android-jni`，role 固定为 `raw-dex`。不得将slot当成文件路径或授权令牌。

单 RAW 入口直接将 Java 数组内容复制到核心记账的自有缓冲，避免额外的 JNI 原始 DEX 中间缓冲；不是零拷贝，VM 自身的内存及其他 JNI 接口的临时副本不属于核心账本。

底层构造单输入 SourceSet，`scope_complete=false`；`SnapshotInfo.sourceScopeComplete` 为 false，snapshot ID 同样编码不完整范围。单个 DEX 的有效元数据不证明它包含整个应用或某个 ClassLoader 的所有来源。`SnapshotInfo` 的数字、SHA-256和snapshot ID是Java拥有的副本；SHA-256是输入身份，不是来源真实性认证。

## 句柄与线程

`Snapshot` 实现 `AutoCloseable`；使用者必须显式 `close()`，重复关闭安全。没有依赖GC、finalizer或Cleaner回收原生资源。单实例的 `info()` 和 `close()` 使用同一Java锁；不同实例可在不同线程使用。关闭之后 `info()` 抛 `IllegalStateException`，之前取得的 `SnapshotInfo` 仍可读。

JNI不把C指针暴露给Java：私有long token映射到进程内受锁保护的持有者，不复用已分配token；token是句柄而非安全授权凭证。最多64个已发布或正在打开的snapshot共同占用配额；槽位在打开失败或关闭后释放。该数量及单输入上限不构成进程RSS、Java数组、所有Engine总体内存或调度延迟的上限。各快照持有独立Engine状态，最后原生引用释放时归还其核心资源。原生lookup在移除前取得的共享持有者可继续完成读取；移除后新lookup返回Closed，Java包装上的同一对象则以锁序列化。异常极端同步故障时保留配额，优先拒绝后续打开。

JNI仅在本次调用线程使用 `JNIEnv`，不保留Java数组指针、局部引用或跨线程JNI环境；不使用CriticalNative、FastNative或逐行Java回调。Java异常已存在时保留原异常；核心非OK状态通过 `NativeFailure.status` 和有界offset报告，诊断消息按可打印ASCII保守显示。进程终止、硬件故障和虚拟机级不可恢复错误不在该保证中。

## 验证边界

仅本机JVM可执行检查、静态包检查和NDK交叉编译能够在此阶段完成；它们不能证明Android设备装载、ClassLoader行为、生命周期压力或ABI在真实宿主中的运行。完整错误注入、所有线程交错、来源集合与设备验收仍待实现。




