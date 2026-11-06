# 显式输入范围的 Android 方法查询 v1

`ScopedMethodQuery` 是通用、显式选择的 method-v1 同步及 Job 入口，接收已有 `NativeEngine.Snapshot` 或 `SourceSetSnapshot` 与 UTF-8 QueryIR JSON。查询必须是直接 `query:v1` 并含 `scope:{slots:[...]}`；未显式scope、其它profile、未知输入slot和超过旧桥工作/结果/JSON限制均明确拒绝。旧 `snapshot.queryMethods` 与 `startMethodJob` 仍拒绝显式scope，其行为不变。

scope只选择调用方提供的 **输入slot**，不是展开后DEX序号；一个多DEX APK会选择该输入展开的全部DEX，零DEX资源slot合法并映射为零来源。返回的 `Scope` 复制编译计划的规范slot列表和同一当前snapshot中选中的有序source indices；后者是静态选中集合，不表示已访问或已成功解析每个候选。空slot列表表示明确的空子集。不存在的slot返回SourceMismatch，不能默默跳过或作为空结果。

`Result.query` 保留核心executionStatus、coverage、decision、reason及候选，`Result.scope` 保留所声明slot和来源索引；结果只对调用方选择的文件子范围成立。即使核心对该子集给出Complete、ProvenTrue或ProvenFalse，`snapshotScopeComplete` 和 `sourceScopeAuthenticated` 始终为false：它不证明安装包、整个应用、ClassLoader或运行时加载集合完整，亦不认证APK签名。显式空范围的不存在判定只对空集合有效。结果为Java复制值，快照关闭后仍可读；没有独立witness或ART验证。

`ScopedMethodQuery.start` 返回包装现有 `NativeEngine.Job` 的Job及同样的声明scope。`next`批次一律provisional，需持续读取至EOS后再检查`status`/`waitFor`终态，不能以某批或EOS代替成功。终态coverage/decision同样只针对声明子集；scope索引表示选中，不证明已扫描。batch/queue/deadline、单消费者next、cancel、close和全局Job容量沿既有method Job合同；快照关闭不撤回已准入Job，显式close仍需调用。同步查询与Job构造时按snapshot实例串行，底层在途请求保活owner；JSON在调用返回前不得并发修改。

JNI从已编译Query的解释接口获取明确slot，并与当前已打开snapshot的原始input元数据逐项核对，再按input_index映射source；同步结果再核对核心返回的范围索引。数组、字符串和结果先构造完成再返回，失败不发布半个Java结果。R8需保留新类/私有构造器和既有NativeEngine嵌套类；不提供loader attestation或完整DEX verifier。
