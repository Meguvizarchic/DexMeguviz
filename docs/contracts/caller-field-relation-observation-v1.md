# caller 声明类与字段声明类的静态关系观察（隔离草稿）

显式要求 `caller_field_relation_observation` 与 `field_declaration_static`，仅适用于现有 v19 的方法左/字段事件右 caller Join/SemiJoin、非空显式 scope；无该能力的旧计划、QueryID、决策和入口不变。观察只对已返回行分类，不是条件过滤；新增能力改变新计划的 QueryID。初版仅同步执行，此能力的 C Job 和旧 JNI 入口返回 Unsupported。

分类按字段定义所在 class occurrence/ordinal 与 caller 方法所在 class occurrence/ordinal 的**静态结构关系**：SELF 为相同身份，ANCESTOR 有一条在所选域内每条边身份唯一的正向路径（不声称全局路径唯一），EXTERNAL 仅在 caller 的可达静态祖先图完全遍历、无缺失/歧义/环且找不到目标时成立，UNKNOWN 表示无法完成确定分类。重复字节、相同 descriptor 的不同 occurrence 不当作同一实体；如果已核验唯一的正向路径存在，不相关缺失/环不影响该静态正向观察，也不证明类图可链接。接口只遍历 superinterface；DEX interface superclass 必须是 Object。证明 EXTERNAL 时，对每个已访问接口须在所选域内确认 Object 唯一、public 非接口、无父/接口且满足受限 flags 模型；缺失、重复或不符合模型均 Unknown。Object 检查不构成接口祖先边。

此前 v19 `declared`/`inherited` 保持相对 field_ref.owner；新增分类相对 caller。ANCESTOR 是结构位置，不证明字段未被同名声明隐藏、可被继承、private/package/protected 可访问、loader 选择或 ART 解析；static/instance 仍先按 v19 决定是否存在可靠字段声明。观察 UNKNOWN 不改变原查询 coverage/decision；数量仅限实际返回行，不能证明被截断或 SemiJoin 未选中事件。未知不伪装成 EXTERNAL。

C 使用 `dmg_result_get_caller_field_relation_witness_v1` 读取独立记录：item 0 为 status/reason、caller class、目标 field/class 和 event 身份；item 1 为节点，item 2 为 EXTERNAL 完整闭包边，item 3 为逐已访问接口的 Object 约定检查（非祖先边）。SELF 包含根节点，ANCESTOR 包含从 caller 到目标的单条正向路径，EXTERNAL 包含全部已检查节点和边，UNKNOWN 仅有诊断头。旧通用见证 getter 对此新 kind 返回 Unsupported；既有 v19 字段声明见证另行读取。证据是引擎对选定 snapshot 的静态断言，不是签名、loader 或独立字节证明；独立校验器必须重新遍历 DEX 才能核对 EXTERNAL 闭包。

Java/Kotlin 使用显式 `queryCallerFieldRelationGraph` 入口和独立双段 wire；已有 v19 图被完整复制，新增分类单独复制并与 caller/event/目标字段身份交叉校验。旧 v19 入口拒绝新能力。JNI 保留 4096 结果、100000000 work、合计 8 MiB wire 限制，Java 对每个结果/证明节点也有限量检查；线协议限制不等于 JVM 堆/RSS。结果复制后可在快照关闭后读取。类型化构造成功并不保证 JNI 预算充足。

图遍历、descriptor 比较、边/节点/环检测和见证物化均走查询 work、Engine scratch/result 预算与 max_intermediate_rows。取消、分配失败、工作或节点上限耗尽不能成为 EXTERNAL 或成功空结果；原调用方仍需分别读取 query 状态、coverage 和 decision。未验证 ART、设备、全量 Q08 或完整 DEX verifier。

接口 Object 约定和唯一性是在证明 EXTERNAL 的闭包过程中检查。若已沿某接口的 superinterface 边找到目标，ANCESTOR 可在检查该接口自身 superclass 之前返回；即使该未检查值非标准，结果也只证明一条静态结构路径，不证明路径节点、类图可链接或 ART 合法。
