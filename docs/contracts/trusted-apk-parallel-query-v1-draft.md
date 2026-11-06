# 可信不可变 APK 并行查询草案

`TrustedApkDexSource` 是显式、可选的纯 Java 输入路径，不替代默认严格 SourceSet。调用方必须明确选择 `TRUSTED_IMMUTABLE_APK`，并保证调用期间所有 APK 路径及内容不变。它通过运行时 `ZipFile` 读取中央目录，仅选取根目录 canonical `classes.dex` 和 `classesN.dex`；验证选中 DEX 的长度和 CRC，**不**验证每个非 DEX 条目的局部结构、APK 签名、强摘要、ClassLoader 或 ART 实际装载字节。文件大小、时间与规范路径前后比较只是辅助检查，不是不可变性或来源认证。

`mapAll` 接受有序 `Input(File, slot, allowNoDex)` 和 `SourceSetLimits`；每项 slot 必须唯一。按输入顺序、每项内按 DEX 数字序返回 `SourceResult`，强制携带 inputIndex、inputSlot、DEX 名、中央目录序号与数字序号；相同字节的不同 occurrence 不合并。每项可独立允许没有 canonical DEX，结果保留空输入及其 slot；这不证明整个 APK 或其他输入无代码。单 APK 的 `map` 是 `mapAll` 包装。调用方显式配置每项和全局归档字节、输入数、条目数、DEX 数、解压字节与线程上限；`ZipFile` 可能在条目上限检查前已为中央目录分配内存。所有 APK 在调用期间同时打开，`maxInputs` 也限制文件描述符数量。

`ParallelDexQuery.mapAll` 在相同有序来源上使用单个有界 worker 池，每个使用方法计划的工作线程拥有独立 `MethodStream`，查询支持 method-v1 与已接通的 reflection-method-uses；纯反射规则可以单独使用。按调用方规则顺序返回每 DEX 结果，通过 `SourceMapper` 可在 Snapshot 生命周期内读取方法调用、类定义等现有事实。方法融合会提前执行方法批次，失败出现的顺序可能改变；不受批量桥支持的计划按单条执行，其余失败不静默重试。每份结果的来源覆盖仍为 incomplete，调用方负责正确聚合范围、绑定成员和业务验证，不能将静态结果或 CRC 当成完整应用的唯一性证明。

执行在所有来源准备完成后启动；空闲 worker 按任务完成情况补位，结果仍按原输入及 DEX 顺序交付。多个任务同时失败时，可能先报告较早完成的错误，不保证按输入顺序选择首个错误；任务异常不会交付部分结果。Mapper 必须线程安全、不对外发布部分结果且不持有 Snapshot。调用同步，失败时取消待执行任务并等待所有已运行 worker 结束后才关闭 ZIP/会话；不能强制中断同步 JNI 或任意调用方代码，因此可能等待较长时间。并发线程至多16（受全进程既有 MethodStream 配额影响）；核心预算按每线程计算，Java 数组、ZIP、Mapper、结果及 JVM 总 RSS 不受此预算限制。

该路径仅完成有限主机验证；Android/ART、实际宿主绑定、R8、冷存储及端到端业务目标尚需独立验证。可自行选择严格 SourceSet，不能把本模式解释为全 ZIP 结构或强来源校验。
