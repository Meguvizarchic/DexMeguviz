# ParallelFastDexQuery 接入契约草案

此候选是通用、按需、并行的 APK DEX 查询封装；不包含 BIL 专用规则。`query` 接受单个 APK，`queryAll` 接受有序 APK 集合；每次接受 1–16 条 QueryIR，并逐条选择是否采集调用边。必须明确提供 `TRUSTED_IMMUTABLE_APK` 和 `CALLER_ASSERTS_VALID_SORTED_DEX`。调用方确保 APK 在调用期间不变、DEX 有效且 ID 表有序；调用方在方法返回前不得并发修改查询数组。封装不认证输入，也不取代严格路径。

结果使用 TrustedApkDexSource 容器，保留输入顺序及每个结果的 inputSlot、输入序号和 DEX occurrence 信息。结果仅为 selected-only 和 caller-asserted；即使所有来源都成功，每条规则仍必须检查 executionStatus、unknownRows、resultLimit 与 callerAssertedExhaustive，空结果不构成完整覆盖或不存在证明。允许无 DEX 的资源包时也预先编译规则，因此不支持的规则仍会报错。

每个活动工作线程独占并复用一份编译计划，来源读取和输出受既有显式限制约束，最多 32 个工作线程。native 计划配额在进程内与其他 FastDexQuery 调用共享，配额竞争可能导致失败；这些限制不涵盖所有 Java、native 和 VM 内存。调用同步运行；来源失败时等待执行中的 JNI 任务退出，关闭已创建的计划，不返回部分来源集合。规则级状态继续交给调用方检查。

该候选仅通过主机 JNI 差分，尚未通过 Android AAR 整包审计、真机业务端到端验收、低端机性能和完整生产兼容性验证。当前计时不含 JVM 启动、Android 类加载、结果绑定和业务选择，不能用于宣称 APK 到业务结果小于两秒。
