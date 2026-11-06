# 源码能力与验收边界

本表按2026-11-02已接入源码记录功能入口，不能当作全部验收通过。工程状态与逐项验收仍以PROJECT_STATUS.json、backlog.json及绑定构建的证据为准；旧AAR不自动获得新源码能力。

## 查询与使用方

| 能力/profile | C ABI与桌面 | Android Java/Kotlin当前入口 | 主要边界 |
|---|---|---|---|
| method-v1 | 方法查询/见证/Job | queryMethods、MethodQuery、Job | 静态范围不等于ClassLoader范围 |
| method-batch-v1 | 有界同步多规则，按需共享事实 | `MethodBatchQuery` 全输入及 `ScopedMethodBatchQuery` 显式范围 method-v1 批量入口 | 每项状态独立，整体失败不返回半数组；无运行中取消/超时，缓存命中不证明提速 |
| entity-v2 | 七类实体 | queryEntities、EntityQuery | Android该入口为直接metadata形状 |
| relational-v3、reflection-relational-v14、reflection-body-relational-v17 | 关系、绑定/连接/证明 | queryGraph、GraphExpression、GraphJob | 各版本独立门控，不接受任意能力混合 |
| use-v4、use-stream-v9、use-target-symbol-v16、inherited-target-symbol-v18 | 使用点及连接/见证 | queryUseGraph/Job及专用scope接口 | 普通v4/v9/v16入口不接受显式scope；专用scoped-v4和v18按合同支持 |
| expand-v5 | 单个展开及外层实体关系、路径/前沿、Job | queryExpand/Job、ExpandQuery、ExpandGraphQuery | 多重/嵌套、高位混合和use主输出仍拒绝 |
| inherited-v6、numeric-v7、interface-v8、interface-resolved-v11 | 各自高级静态模型与专用见证 | queryAdvanced/Job；v6及v8/v11使用点图有独立同步/Job入口 | v6/v8/v11使用点形状按专用合同；numeric-v7使用点图及任意能力组合不自动支持 |
| composite-v10、unique-one-v12 | 已有专用核心语义 | 尚无对应完整Android入口 | 不从core能力字符串推断JNI已支持 |
| reflection-flags-v13 | 直接静态反射flags | 单独v13没有通用实体入口；可用已支持v14图形表达相应metadata需求 | 不是运行时反射结果，Unknown保留 |
| reflection-method-uses-v15 | 反射flags与方法体条件 | queryReflectionMethodUses/Job、对应Kotlin入口 | 要求实际body demand且满足该profile门控 |
| field-declaration-v19 | 字段声明静态解析 | queryFieldDeclarationGraph、FieldDeclarationQuery | 显式受限解析形状 |
| reflection-class-annotations-v20 | 类注解静态flags | queryClassAnnotationGraph、ClassAnnotationGraphQuery | 注解模型不是ART运行验证 |
| type-uses-v21、method-type-uses-v22 | 类型使用点/同方法组合 | queryTypeUseGraph/Job、queryMethodType/Job | scope及组合按专用合同；同方法不等于同一可执行路径 |
| caller-field-relation observation、selected-method-calls-v1 | 显式事实/观察入口 | queryCallerFieldRelationGraph、inspectMethodCalls | 调用事实操作不伪造QueryID/全局decision；仍非运行时绑定 |
| opcode-sequence-v23 | 显式直接方法序列四模式及可选计数 | `OpcodeQuery.execute` 同步及非范围 `startJob`；Kotlin可调用Java入口 | `ScopedOpcodeQuery` 提供独立显式输入slot子范围；范围同步组合AAR/R8固定主机样本通过，范围Job未提供；非范围Job仅JNI主机样本，待组合AAR，负数通配和signed16转换须独立显式启用，真实DexKit/ART/性能未验 |
| class-annotation-string-v25 | 类注解显式字符串元素按来源局部 UTF-16 等值查询；C/CLI | 独立全输入与显式范围同步/异步桥 | 独立能力与QueryID，缺省为Unknown；复杂注解、设备与性能未验 |
| class-annotation-static-v24 | 类注解类型、可选可见性及单个顶层整数元素；C/CLI | `ClassAnnotationQuery` 全输入及 `ScopedClassAnnotationQuery` 显式输入槽同步/异步查询 | 旧能力位图不可表达，需v2信息接口；复杂注解、设备与性能未验 |
| selected-method-facts、method-parameters | 选定方法的使用/指令事实与静态原型/debug参数名 | `inspectMethodFacts`、`inspectMethodParameters`及Kotlin入口 | no-body/no-debug等状态分离；不等同运行时反射或全APK结论 |
| DEX 来源分块导出 | C ABI 提供单来源只读字节视图 | `DexStreamExport` 按单来源或来源集合向调用方输出流分块复制，带预算 | 不创建路径、不关闭或刷新流；异常可留下部分输出；设备/ART及真实性能未验 |
| 静态注解与来源局部符号 | 注解原始编码、string/type/proto文本及字段/方法引用索引 | `Annotations`、`EncodedValue`、`AnnotationMatcher`、`AnnotationArrayMatcher`、`BoundAnnotationText`、`DexSourceExport`对应入口 | 引用按来源局部解释；`AnnotationMatcher` 仅显式标量/来源局部索引及调用方解析的文本，`BoundAnnotationText` 核对静态身份但不认证运行时来源；数组提供一维精确、有序子序列及无序标量一对一匹配；嵌套条件、默认值、DexKit语义对照及loader认证未完成 |

版本化getter只返回其能表达的结构；旧getter对不兼容结果明确Unsupported，不能读取半份新见证。各精确shape见docs/contracts及bindings/android/docs；未列出的组合不自动承诺支持。

## 来源、平台和可选模块

| 范围 | 已有实现 | 验收边界 |
|---|---|---|
| DEX035/037/038/039/040 | 复制/借用/FD、有序raw/APK、多DEX/资源split、强摘要与来源出现 | checked子集不是完整ART类型verifier；摘要非认证 |
| 实验DEX041 | 显式C复制容器/专用桌面CLI、双基址与共享后续数据 | 默认入口、SQL、Android/借用/FD及其他未接decoder路径仍拒绝；缓存绕过041 |
| Android来源与binder | raw/SourceSet/APK FD和显式描述符绑定 | 迭代258 AAR双ABI与选定主机JNI/binder/R8检查通过；单台API33/arm64/4KiB设备运行当前自建样例9/9，完整接口、来源认证和ART未验 |
| 桌面SQL | catalog/约束/投影/IN、严格提交/分页、同步与后台驻留、BLOB、有序来源和一次性入口 | DMG_WITH_SQLITE显式启用，Android禁用；S01-S11/压力/正式性能待统一 |
| 持久facts | 显式provider、方法/use/展开/反向索引路径、正负符号域缓存；桌面SourceSet工具和独立C ABI；Android显式opt-in同步方法缓存 | 默认关闭、信任目录写者；Android opt-in构件早于最新源码，需重建；非完整L1/任意查询缓存，F12/设备/资源专项待验 |
| 离线预解算 | 桌面包生成/消费、独立期望与局部字节核验 | 纯JVM/Android消费及BIL11规则显式政策桥已接源码；不证明producer Unique/absence或发行认证，默认回退，producer接受不写普通L0 |
| CFG/有限dataflow/结构排序 | 按需内部实现与桌面工具，显式保守模式 | 结构可达不等于路径可行，分数非概率，真实跨版本/设备与完整专项待验 |
| BIL33规则 | 静态计划33项、专用辅助、A/B/C对照runner及宿主桥；29项单规则候选守卫、Sponsor三规则及Story DEFAULT+MATCH同批候选路径均默认关闭 | 同批路径与若干规则只支持受限形状，生产启用0；真实BIL仍依赖DexKit，完整原始袋/业务/设备/Hook及A/B/C未验 |

## 当前证据分层

- 迭代258双ABI AAR、Windows JNI、固定Java/Kotlin消费者和R8经两次路径纠错续跑通过；迭代259桌面构件已构建但未执行，97项共同生产输入核对一致，本地候选仍未认证/发布。
- 一台SDK33、arm64、4 KiB页设备运行迭代260自建sample，v24/v25与MethodBatch九项检查通过；不能外推其他设备、完整ART、真实BIL或Hook。
- Android可选持久缓存AAR早于当前接口改动，需重新按当前源码构建并验证；未验证其当前版本设备行为。
- 基准runner只有自建夹具连通，正式语料/门禁与性能结论未完成；不会借桌面数据声称BIL A/B/C通过。
- 先前被过滤的v5模糊测试未重试；其证据缺项仍保留，不由其他检查替代。

新增源码能力与验收完成是两件事；所有任务仍按原验收逐项收口，部分结果不升级成完整SDK或BIL生产替换。
