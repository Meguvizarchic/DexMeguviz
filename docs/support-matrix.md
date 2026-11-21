# 源码能力与支持矩阵

本矩阵按源码已接入的功能入口整理各能力、平台支持与限制边界。未在表中列出的跨版本能力组合不自动保证支持。

## 查询 Profile 与使用方式

| 能力 / Profile | C ABI 与桌面端 | Android Java/Kotlin 入口 | 主要边界 |
| --- | --- | --- | --- |
| `method-v1` | 方法查询、见证与 `Job` | `queryMethods`、`MethodQuery`、`Job` | 静态输入范围不代表运行时 `ClassLoader` 范围 |
| `method-batch-v1` | 有界同步多规则批量查询，按需共享扫描事实 | `MethodBatchQuery`（全输入）与 `ScopedMethodBatchQuery`（显式范围） | 单条规则失败导致整批失败，不返回半截结果；不支持运行中取消或超时，缓存命中不保证绝对提速 |
| `entity-v2` | 七类基础实体查询 | `queryEntities`、`EntityQuery` | Android 该入口仅面向直接元数据查询形状 |
| `relational-v3`、`reflection-relational-v14`、`reflection-body-relational-v17` | 关系查询、绑定/连接与证明 | `queryGraph`、`GraphExpression`、`GraphJob` | 各版本独立门控，不接受跨版本任意混合 |
| `use-v4`、`use-stream-v9`、`use-target-symbol-v16`、`inherited-target-symbol-v18` | 指令使用点、连接与见证 | `queryUseGraph` / `Job` 及专用 scope 接口 | 普通 `v4`/`v9`/`v16` 入口不接受显式 scope；`scoped-v4` 与 `v18` 需按专用契约调用 |
| `expand-v5` | 单次有界展开及外层实体关系、路径/前沿与 `Job` | `queryExpand` / `Job`、`ExpandQuery`、`ExpandGraphQuery` | 拒绝多重或嵌套展开、高位混合以及以 use 作为主输出 |
| `inherited-v6`、`numeric-v7`、`interface-v8`、`interface-resolved-v11` | 各自高级静态模型与专用见证 | `queryAdvanced` / `Job`；`v6` 与 `v8`/`v11` 使用点图提供独立同步/`Job` 入口 | `v6`/`v8`/`v11` 使用点图须遵循专用形状；不支持 `numeric-v7` 使用点图及任意能力拼接 |
| `composite-v10`、`unique-one-v12` | 已实现专用核心语义 | 尚无对应完整 Android 入口 | 不可仅凭核心能力字符串推断 JNI 端已支持 |
| `reflection-flags-v13` | 直接静态反射标志 | 单独 `v13` 无通用实体入口；可通过已支持的 `v14` 关系图表达 | 不等同运行时反射结果，保留 `UNKNOWN` 状态 |
| `reflection-method-uses-v15` | 反射标志与方法体联合条件 | `queryReflectionMethodUses` / `Job` 及对应 Kotlin 入口 | 要求实际方法体读取需求且满足该 profile 门控 |
| `field-declaration-v19` | 字段声明静态解析 | `queryFieldDeclarationGraph`、`FieldDeclarationQuery` | 仅支持显式受限的静态解析形状 |
| `reflection-class-annotations-v20` | 类注解静态标志 | `queryClassAnnotationGraph`、`ClassAnnotationGraphQuery` | 静态注解模型不代替 ART 运行时校验 |
| `type-uses-v21`、`method-type-uses-v22` | 类型使用点与同方法共现组合 | `queryTypeUseGraph` / `Job`、`queryMethodType` / `Job` | 作用域与组合遵循专用契约；同方法出现不等于同一可执行路径 |
| `caller-field-relation`、`selected-method-calls-v1` | 显式事实与调用关系观察入口 | `queryCallerFieldRelationGraph`、`inspectMethodCalls` | 调用观察不伪造 `QueryID` 或全局 decision，仍非运行时绑定 |
| `opcode-sequence-v23` | 显式直接方法指令序列四模式及可选计数 | `OpcodeQuery.execute` 同步与非范围 `startJob`；`ScopedOpcodeQuery` 同步入口 | 范围 `Job` 暂未提供；负数通配和 signed16 转换须显式启用 |
| `class-annotation-string-v25` | 类注解显式字符串元素按来源局部 UTF-16 等值查询（C / CLI） | `ClassAnnotationStringQuery` 与 `ScopedClassAnnotationStringQuery`（同步与 `Job`） | 独立能力与 `QueryID`，缺省返回 `UNKNOWN` |
| `class-annotation-static-v24` | 类注解类型、可选可见性及单个顶层整数元素（C / CLI） | `ClassAnnotationQuery` 与 `ScopedClassAnnotationQuery`（同步与 `Job`） | 旧版 32 位能力掩码无法表达，须通过 `v2` 信息接口读取 |
| `selected-method-facts`、`method-parameters` | 选定方法的使用/指令事实与静态原型/调试参数名 | `inspectMethodFacts`、`inspectMethodParameters` 及对应 Kotlin 入口 | 明确区分 `no-body` / `no-debug` 等状态，不等同于全 APK 或运行时结论 |
| DEX 来源分块导出 | C ABI 提供单来源只读字节视图 | `DexStreamExport` 按单来源或来源集合向调用方输出流分块复制 | 不负责创建路径、刷新或关闭流；异常中止时可能留下已写入的部分字节 |
| 静态注解与来源局部符号 | 注解原始编码、string/type/proto 文本与成员引用索引 | `Annotations`、`EncodedValue`、`AnnotationMatcher`、`AnnotationArrayMatcher`、`BoundAnnotationText`、`DexSourceExport` | 引用按来源局部解释；数组支持精确、有序子序列与无序标量一对一匹配，暂不支持嵌套条件与默认值推断 |

版本化 getter 仅返回自身可表达的结构；旧版 getter 遇到不兼容结果时会明确返回 `Unsupported`，不会输出半截数据。各接口精确形状见 `docs/contracts/` 下的对应契约文档。

## 来源、平台与可选模块

| 模块 / 范围 | 已有实现 | 边界说明 |
| --- | --- | --- |
| DEX 035/037/038/039/040 | 复制/借用/FD 打开、有序 raw/APK 来源、多 DEX 与空 DEX 资源 split、SHA-256 与来源出现身份 | 检查子集不能替代完整 ART 类型验证器；哈希摘要不代表签名认证 |
| 实验 DEX 041 | 显式 C 复制容器入口（`dmg_snapshot_open_dex041_copy_v1`）与专用桌面 CLI（`dexmeguviz_041`） | 默认入口、SQLite、Android 端及借用/FD 路径均拒绝 041，持久缓存绕过 041 |
| Android 来源与绑定辅助 | `raw`、`SourceSet`、APK FD/路径及显式 `RuntimeMethodBinder` / `RuntimeMemberBinder` | `loader` 身份由调用方声明，不认证签名、安装来源或完整 ART 可见性 |
| 桌面 SQLite 入口 | 目录/约束/投影/`IN`、严格提交分页、同步与后台驻留、`BLOB`、有序来源与一次性入口 | 仅在 `-DDMG_WITH_SQLITE=ON` 构建中启用，Android 端禁用 |
| 持久化 facts 缓存 | 显式 provider、方法/use/展开/反向索引与正负符号域缓存；桌面工具与独立 C ABI | 默认关闭，缓存目录写者须由调用方信任；非任意通用查询缓存 |
| 离线预解算 | 桌面打包（`tools/precompute/package.py`）与消费、独立期望与局部字节核验 | 不证明生产者全局 `Unique` 或 `absence`，不支持的形状默认回退 |
| CFG / 有限数据流 / 结构排序 | 按需内部实现与桌面工具（`dexmeguviz_dataflow`、`dexmeguviz_correspondence`） | 结构可达不等于运行时路径可行，排序分数非概率估计 |
| BIL 33 项规则相关适配 | 静态计划、专用辅助与对照 runner；29 项单规则守卫及部分同批路径默认关闭 | 默认生产启用数为 0，仅支持受限形状 |

## 适用范围与验证说明

- 源码新增能力不等于全平台或全语料验收完成；项目进度、逐项状态及具体绑定构建证据以 `PROJECT_STATUS.json` 与 `backlog.json` 为准，早期发布的 AAR 不会自动获得最新源码能力。
- 既有的主机 JVM 测试、单机样本验证、R8 固定样本检查与桌面连通性检查均有各自的适用边界，不能外推为全量设备、完整 ART、完整性能优化或跨平台发布验收结论。
