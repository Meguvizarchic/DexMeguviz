# APK SourceSet 方法观察与显式绑定草稿

`MethodSourceObservation.query(opened, queryJson)` 在同一 `AndroidApkSources.Opened` 的快照锁内获取元数据并执行 method-v1 查询。它不接受外部 QueryResult，不打开新文件或另一个快照；并发 close 与查询串行。查询必须投影 owner/name/prototype，否则抛出失败。方法检查 plan/input 顺序、slot、allowNoDex、APK摘要、source→input、DEX摘要、entry/index、occurrence唯一性、候选索引与snapshot/query身份；资源-only APK仍保留input。它只核对本次 native API 提供的观察，不是独立DEX verifier、签名验证或 loader 来源认证。

结果保留 executionStatus、coverage、decision、reason、unknownRows、visited/total，`observedCandidateCount` 只表示已观察候选数。`allInputMethodsScanned` 仅在成功、非ResultLimit、无Unknown且visited==total时为真，描述本次输入，不等于应用/loader完整；即使已遍历全部输入，EXISTS、UNIQUE、TopN 等意图仍可能只返回代表性候选，不能据此宣称候选列表完整；`sourceScopeComplete` 原样保留，Android来源固定false。早停、Unknown或ResultLimit仍可保留已观察的逐项候选，其 `inputScanIncomplete` 为true；零候选及候选数量均不证明全局缺失或唯一。原生错误抛出而不是变为空成功。内存/时间、文件并发变化、hash ABA和来源/loader后续变化均不由此证明。

逐候选 `bind(loader,generation)` 是显式动作；必须先在计划中提供同一 loader/generation 对象引用，否则拒绝。绑定沿用 `RuntimeMethodBinder`，始终 Origin.UNVERIFIED；initiating与defining loader分开，父委派合法，token仅为调用者身份声明。绑定可能执行自定义ClassLoader代码或加载/链接类型，不请求初始化、不修改可访问性、不调用目标。复制的结果可在快照关闭后访问，但不能证明loader/文件此后未变。方法及目标对象仍可能由调用者改变。本桥不做业务选择、不取代逐archive 32上限、旧解压顺序或 DexKit兼容，并不接入BIL、设备、ART或业务。
