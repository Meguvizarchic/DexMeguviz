# JNI v6 继承与使用点关系图

新增显式 `Snapshot.queryInheritedUseGraph`、`SourceSetSnapshot.queryInheritedUseGraph` 及对应 `startInheritedUseGraphJob`；Kotlin 的 `InheritedUseGraphExecution` 接收 `AdvancedQuery`，由native编译器和独立准入门控确定真实形状。入口只接 `query:v6:`、同时具有 inherited_fields 与 use_relations 的native图，支持其原有显式顶层/扫描scope和字符串/调用/字段使用点；v4/v9/v16/v18、数字/接口/组合及其他高级profile不通过此入口。旧 `queryUseGraph` 和 `startUseGraphJob` 的准入不变。

结果复用 `UseGraphResult` 的继承见证wire：保留typed entity/use值、PC和引用域、连接、角色与证明、每个 inherited leaf 的 item/path/aux/branch/detail；路径解释遵循 `inherited-query-v6.md`，不得将来源候选视为运行时解析。带显式scope时可按核心返回静态域Complete，但它是调用方声明，不认证ClassLoader或全应用来源。不同来源出现及Unknown、coverage和decision分开。结果复制后可在原快照关闭后读取。

Job与已有use graph Job相同：单消费者、每批provisional、需读到EOS再检查终态；v6不启用v9扫描内早交付能力。输入JSON、查询、wire、来源与队列限制沿用 `jni-use-graph-job-v1.md`。复制/解码失败取消并污染流，不能把已有批次作为最终成功；错误、取消、预算或缺失来源不转成空结果。显式scope仅约束所声明来源，不能推断真实设备完整性。

固定Windows JVM/JNI样本只证明对应静态行为；不证明所有 v6 关系组合、设备、ART、运行时绑定或BIL业务。
