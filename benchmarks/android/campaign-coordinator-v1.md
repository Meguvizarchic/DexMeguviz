# 实验性 A/B/C 顺序采集协调器

`CampaignCoordinator` 将调用方明确提供的三个 `Backend`、逐次环境检查、`TaskProbe` 和 `CampaignJournal` 串联。它按当前 `benchmarks/protocol.v1.json` 中固定顺序，对 cold、完整 L0、已打开 snapshot 的 warm、前台四个 case，分别执行5个warmup及30个measured三元组；持久facts由调用方显式启用并增加第五case。每次执行前后核对后端提供的构件身份，并调用 `Environment.before/after`；每个后端须在回调返回前完成完整任务及同步释放，并按顺序标记prepared、firstAnswer、closing。

先构造 `Plan(protocolSha256, identitySha256, declaredOrder, backendBuilds, expectedProjections, persistentFacts)`；每个case须预先给出64位小写projection摘要，三个后端构件身份须显式提供，输入被复制。调用方须从已冻结的实际协议核对并提供顺序，协调器检查其与内置顺序一致；单靠调用方声明不证明协议文件的内容。journal 必须仅包含新建的头部，其协议、身份摘要须与 Plan 相同，身份 JSON 原始字节摘要须与声明的身份摘要相同；这不认证身份，也不验证 JSON 规范性，恢复器仍会独立检查规范 JSON。旧的四参数 Plan 构造器保留二进制链接，但不能作为未绑定计划运行，调用方需迁移到新构造器。任一预检失败均在调用任何后端方法前拒绝，保留未完成日志。

调用 `run(plan, backends, environment, CampaignCoordinator.measureWith(probe), journal)`；运行期间协调器独占 journal，外部 append、finish、close 及另一协调器竞争均被拒绝。`Result.allScheduledRecorded=true` 只表示所有尝试已记录且满足本地继续条件，**不是性能、兼容或发布验收**。成功时释放独占权，journal仍由调用方持有，只有独立外部门禁证据准备好后才可显式 `finish`；不finish即为不完整。

实际运行前后需由宿主自行完成APK/设备/loader/配置身份、重置策略、温度和电量、真实结果投影、结果和资源生命周期等验证；`before/after` 的true只是调用方声明。`before` 必须在返回false或抛错前自行回滚其副作用（此时不调用after）；调用期间不得并发修改后端返回的观察Map及其嵌套值。检查本身应预先固定、对A/B/C相同，并评估校验导致的页缓存或环境影响。后端只返回实际观察，不得声称未测字段成功；调度/身份字段由协调器填充，冲突会使本行不完整并停止。协调器仅读取记录桥支持的字段和可选的调度/身份冲突声明，不遍历任意未知键；调用方必须另行保存被忽略的原始观察。已读取字段的Map序列化失败时只能保存错误类别，调用方必须另行保存无法序列化的原始观察。

任一前置拒绝、身份变化、测量异常、后置拒绝、结果缺失、正确性或projection不一致、漏采/截断/边界不完整均先尝试追加失败行，随后关闭journal且不写footer；写入/序列化失败会向调用方抛出，已写前缀不删除，无法保证严重VM错误或真实I/O故障时完整保留。任务或环境中断会尝试记录原因、恢复线程中断标志；若文件系统在写入期间再次中断，文件可能只剩部分前缀。既有journal受单一写者和可信私有目录约束；协调器不执行设备控制、安装、强停、网络、自动清理或Hook。

`registeredOrder()` 是当前预登记30组三元组的固定副本；调用方必须在正式C数据前把协议文件冻结并确认副本一致。若协议变更，需重新审查并版本化协调器；分析器仍以最终协议的实际顺序、完整行、身份和外部门禁为准。使用注入的 `Measurement` 可以做主机合成控制，真实采集应显式使用 `measureWith(TaskProbe)`；注入值和所有事实都不能自证真实性。当前只验证Java 8主机合成调度和假PSS；没有真实A/B/C后端、Android/ART、设备、前台帧采集、温度策略或性能结论。

## 从冻结协议准备调用参数

`python tools/prepare_android_campaign.py <协议文件>` 仅读取协议并将计划输入写到标准输出；草案、关键字段缺失、身份结构错误、与 v1 固定顺序/门槛不符时以退出码 2 和 stderr JSON 拒绝。输出包含原始协议字节 SHA-256、与分析器一致的 canonical identity JSON 及 SHA-256、顺序、构件身份和期望投影；该输出可能含本机/设备身份，应由调用方按私有证据处理。准备结果仅反映声明的协议，不认证真实设备、APK、构件、项目状态或测试通过。协调器仍在执行前独立检查声明顺序和 journal 头，分析器及人工外部门禁仍需独立核对。

此工具 v1 要求每个有序 APK 来源使用 `slot`、`package`、`versionName`、整数 `versionCode`、正整数 `byte_length`、`sha256` 和 `intake_revision`；slot 必须唯一。每个 A/B/C 构件使用 `source_commit`、`artifact_sha256`、`toolchain_lock_sha256`、`build_flags`，并明确 `clean=true` 或提供 `dirty_patch_sha256`，不得同时声称干净与有改动。实际身份字段和哈希的来源须在真实运行前独立核实；这是准备工具自身的输入格式，不能将脚本输出作为身份真实性证据。协议/身份格式改变须先更新并复核工具，不能为了通过预检擅自调整性能门槛。
