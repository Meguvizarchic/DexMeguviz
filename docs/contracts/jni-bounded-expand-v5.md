# Android / Kotlin 有界展开接线

新增独立 `queryExpand` / `startExpandJob`，通过现有 snapshot / SourceSet token 注册表、Job 配额和生命周期进入 v5。Kotlin `ExpandQuery` 提供方法图输入、方向、深度、路径/端点、scope、walk/emit 条件和预算；ExpandQuery 保留根展开入口；GraphExpression.expand 与 ExpandGraphQuery 可类型化组合既有实体关系运算，原始 JSON 入口也接受核心已经实现的实体结果组合。其他 profile 的旧入口不扩展接受范围。

JNI 使用私有 little-endian wire，沿用 8 MiB、100000 项和 1048576 个 UTF-16 单元上限；二进制为本次 Java/JNI 内部协议，不作为持久格式。完整复制结果行实体、外层行 bindings/links/proofs/witnesses、有序 paths/hops、seed 绑定与证明、walk/emit 证明、未知和未解析 frontiers、来源出现身份、coverage/decision 及 profile。行实体不必等于附属路径 endpoint；最终 use 主输出仍由核心拒绝。

`ExpandResult.Row.value` 是组合后的实体；`Row.evidence` 是外层行证据，各 Path 和 Frontier 分别持有自己的证据和有序 hop。Source/Input 保留发生位置与哈希等静态身份，并不认证加载来源。同步/批次结果提供实际 scope source 索引；Job 状态的 C 接口未提供该索引列表，`scopeSourcesKnown=false`，但保留 profile 的 scopeSourceCount/scopeComplete、整个 snapshot 来源元数据及 QueryID，不能把空索引列表误认为空查询范围。

`ExpandJob.next` 使用单消费者约束，批次 wire 或 Java 解码失败后标记交付失败并取消/阻止后续成功状态。status/wait 使用 expand 专用终态接口；即使零结果行，终态仍可获取 frontiers。运行中状态不枚举会变动的完整 profile/frontier 数组；终态再读取。EOF 不替代 executionStatus/coverage/decision。close/cancel 沿用现有并发 token 约定。

本轮 Java 17、Kotlin 2.4.21 和 Windows JNI Release 编译通过，并做了同步路径、Job 分批及零行终态前沿的连接性烟测。最终 JNI 编译绑定新增外层行证据 getter 的 composition 核心候选。初次 Java 编译遗漏 Android stub 类路径而失败，原始日志保留。注册表已添加 JNI 方法、Java/Kotlin 类和精确 decode keep 规则；没有运行专项 ABI/R8/故障验证、Android 双 ABI 构建或设备/ART，现有 AAR 不代表本轮接线。

GraphExpression记录展开节点数量：最多一个，禁止嵌套/多重和reflection混合。GraphQuery仍仅用于不含展开的旧关系图；ExpandGraphQuery要求恰好一个展开，调用ExpandExecution的同步/Job重载，保持外层结果实体与路径终点分别传输。类型化组合的连通检查见iteration137，完整专项尚未执行。
