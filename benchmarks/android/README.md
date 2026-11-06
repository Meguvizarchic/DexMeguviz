# Android 任务 PSS/耗时采集组件（实验）

这两个 Java 文件是可嵌入测试宿主的测量组件，不是正式 A/B/C runner。`TaskProbe` 接收可注入的单调时钟与读取当前进程 PSS 的实现；`AndroidTaskProbe.create(maxSamples)` 使用 Android `SystemClock.elapsedRealtimeNanos()`、`Debug.getMemoryInfo` 和 `getTotalPss`（KiB 转字节）。[Android 单调时钟](https://developer.android.com/reference/android/os/SystemClock) 适合间隔测量；[Android Debug](https://developer.android.com/reference/android/os/Debug#getMemoryInfo(android.os.Debug.MemoryInfo)) 说明低层进程内存读取可能遗漏受保护分配（例如部分图形分配）。PSS 采样结果是观测值，不是精确峰值或全部资源成本。

`measure` 先分配采样缓存并启动采样线程，在 admission 前按 10 ms 目标间隔取得31项基线；任务从 admission 开始，并须在回调返回前完成同步释放。任务依次调用 `prepared()`、`firstAnswer()`、`closing()`；前两项为自 admission 累计纳秒，close 为 closing 至回调返回的纳秒，完整耗时包括全部回调时间。标记错误或缺失使 `localSampleComplete=false`。业务提交、每项来源、缓存、线程和结果等价需由宿主独立证明，不在此推断。

任务期间按 10 ms 目标间隔测当前进程 PSS；每项记录予定时间、读开始/结束单调时间及 PSS 字节。捕获到的读取异常或 LinkageError 使用 `pssBytes=-1` 保存失败项并记 failureClass；时钟故障或其他错误也会使采集不完整；累计记录漏掉的计划采样位置，超过 `maxSamples` 标记截断。耗时内没有有效样本、基线/期间有漏采或读取失败、截断、标记缺失、任务异常或采样线程未结束时本地采集不完整。已发生的阶段标记保留，任务异常和采样异常分别保留异常类名。`rawSamples` 原样保留所有已开始读取的采样，包括跨结束边界的样本；尚未返回的读取以结束时间及 PSS 均为 `-1` 标记。`samples` 仅包含任务结束前完成的读取，峰值只使用该集合。如果计划读取应在任务内发生却跨越结束边界（包括读取开始于结束之后），`boundaryIncomplete=true` 且增量峰值为 `-1`，即使此前已有有效样本也不能判定本地采集完整。漏采根据任务起止间的全部 10 ms 计划时点与按时完成的成功采样计算，即使工作线程在任务结束后才醒来也不会漏算；任务未能给出可靠结束时间时漏采为 `-1`。漏采只统计任务结束之前的计划时点；最后一次基线之后不会凭空添加下一基线漏采。观察到的增量峰值是时间包络内有效 PSS 样本最大值减去31项基线中位数，最低为零；采样跨结束边界的不计入；基线或有效包络内任一样本无法读取时，增量峰值为 `-1`（不可得），不能代替零。真实执行仍须保存原始样本、缺失与原因，并按预注册协议判定，不能丢弃慢值或将空样本改为零。

调用方应为 A/B/C 使用相同的探针配置与任务包络，提前完成探针自身类初始化并采用相同前置条件。`measure` 本身不验证后端、结果、来源、进程身份或缓存状态，不采集线程/CPU/RSS、warm查询序列、前台帧、温度或环境状态，不生成分析器需要的完整记录；不可据此把 `formal_runner_ready` 标为 true。若测量器读取阻塞，基线最多等待30秒、结束等待5秒，不强制终止线程；采样线程未退出时该实例拒绝再次使用，并返回已记录的基线、在途采样、已有阶段标记、任务错误和采样超时状态。采样与失败的同时快照受同步保护；极端致命 VM 错误仍可能直接向调用方传播，不能保证记录完整。任务自身不设超时，宿主须独立管理任务和整体超时。采集数据由调用方显式持久化；本组件不写文件、不上传、不安装应用、不操作其他进程。

宿主连通测试使用注入的合成 PSS 与真实 JVM 单调时钟，覆盖基线、采样、缺失、任务失败和截断/重入；Android 适配代码仅针对已安装 SDK 的 android.jar 编译，尚未在 Android/ART 设备运行。本目录不包含 DexKit，不改变 SDK 生产依赖。

单次采集结果可通过 [实验记录桥](record-bridge-v1.md) 转成分析器 record；身份、正确性和环境依然由调用方提供且未认证，顶层 campaign 及正式验收仍未实现。

实验性 [追加日志与恢复](journal-v1.md) 可保留单次记录、故障与截断尾部并转换为分析器输入；它不执行后端或认证真实性。

预登记次序的实验采集协调器及失败封闭边界见 [campaign-coordinator-v1.md](campaign-coordinator-v1.md)；它不提供真实A/B/C后端或设备操作。
