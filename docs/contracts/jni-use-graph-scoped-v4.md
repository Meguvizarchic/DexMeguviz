# 独立显式作用域 v4 use-graph 同步接口

`Snapshot.queryUseGraphScopedV4` 和 `SourceSetSnapshot.queryUseGraphScopedV4` 是独立 opt-in；仅接受 QueryIR 的顶层 `scope.slots` 明确存在且核心规范身份为 v4 的 use-graph。只在 scan 节点写 scope、不指定 scope、v9/v16/v18 和其他 profile 均返回 Unsupported。原 `queryUseGraph` 对 v4/v9/v16 显式 scope 的拒绝与对 v18 的既有支持不变，Job 未扩展。

scope 是调用者对指定输入槽构成静态查询域的声明。核心将顶层和 scan 级 scope 求交，验证槽存在，明确空列表表示空静态范围；一个 APK 槽包含它的全部展开 DEX，资源-only 槽可以不含 DEX。结果保留核心 coverage、decision、Unknown、scope 来源、事件、证据与 QueryID。局部范围 Complete 不证明整个应用、所有 ClassLoader 或运行时绑定完整；snapshot 原始 sourceScopeComplete 仍为 false。

复用既有结果私有 wire 和复制式 `UseGraphResult`，结果在快照关闭后保活；沿用 JNI 查询64 KiB、结果4096行、工作100000000、wire 8 MiB 和现有来源限制。错误不返回半结果，ResultLimit 是带执行状态的成功句柄。无新 C ABI、生产依赖或默认行为。

Kotlin `ScopedInvokeSiteQuery` 构造有界的单扫描并快照槽名；`ScopedUseGraphExecution` 也可显式转发其他 v4 原始 JSON。槽名与来源入口同样限定为1–128个无空格可打印 ASCII，最多8个且不允许重复；空列表允许，槽不存在仍由核心报错。固定主机样本不能代替 ART、设备或真实业务验收。
