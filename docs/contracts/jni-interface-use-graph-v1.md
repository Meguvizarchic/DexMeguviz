# JNI v8/v11 接口继承与使用点关系图

新增显式 `Snapshot.queryInterfaceUseGraph`、`SourceSetSnapshot.queryInterfaceUseGraph` 及对应 `startInterfaceUseGraphJob`；Kotlin `InterfaceUseGraphExecution` 接收 `AdvancedQuery`，由native编译器和独立门控确定实际形状。仅接收同时具有 use_relations 的 v8 `interface_fields` 或 v11 `interface_resolved` 图；v6、v9、v10、v16/v18、数字/其他高级混合profile不通过此入口。旧入口的准入不变。

结果为 `UseGraphResult`，新私有wire保留 tagged entity/use、调用点、来源、绑定、证明、链接，以及每条接口见证的节点、匹配三值、关系算子、来源、实体关系/序号、item、branch、node、aux、detail；`interfaceDetailPresent` 为真时五个 interface 字段可用，`interfaceResolved` 区分v11；未提供字段为0xffffffff。v8 item范围0–5，v11范围0–6，后者保留多定义选择。字段/索引语义见 `interface-query-v8.md`、`interface-resolved-v11.md`；不把静态路径视作ART或ClassLoader绑定。

顶层或Scan显式scope允许按核心完成静态范围，但仅为调用方声明，不认证全应用来源。不同 occurrence、Unknown、coverage和decision保持分离。复制结果独立于原生句柄；数据、时间、来源与wire限制沿用 `jni-use-graph-job-v1.md`。Job批次provisional，必须读到EOS并检查终态；v8/v11不启用v9扫描内早交付。错误、取消或复制失败不会作为成功空集。

当前固定主机样本覆盖含接口边、接口字段、多定义选择的v8/v11同步与Job，不证明全部拓扑、资源边界、Android/ART/设备、真实BIL或完整Q08。
