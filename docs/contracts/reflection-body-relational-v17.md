# 静态反射与方法体谓词的关系查询 v17

显式同时声明 `reflection_flags_static`、`reflection_relational` 和 `reflection_body_relational`（新能力位 `33554432`），关系表达式须包含 reflection flags 谓词和至少一个 `using_strings`、`invokes` 或 `field_access` 方法体谓词。QueryID 使用 `query:v17:` 和编码域 `DexMeguviz:QueryIR:reflection-body-relational-v17`。未声明组合能力、缺少 reflection 或方法体谓词、或直接查询而非关系表达式均返回 Unsupported；旧 v13–v16 计划和 QueryID 不变。

方法体谓词仅适用于 `method_defs` 的 Scan/Filter；可与既有纯元数据 Scan/Filter/Label、Union/Distinct、GroupByOwner、Join/SemiJoin、作用域、排序及意图按既有关系契约组合。不能混用 use-event 根、target_symbol、numeric、继承、接口解析、use-streaming、composite、unique-one 或 v15 独立方法查询能力。未支持的组合明确拒绝，不把不可得事实当空集。输出 `access_flags` 仍是原始 DEX 位，`domain:"reflection"` 只改变该谓词的比较域。

静态反射投影和 Unknown 语义沿用 `reflection-flags-v13.md`；方法体通过按需 checked 解码，All/Any 先判断纯元数据以支持安全短路。关系行、来源、角色、证明、三值、失败和预算沿 `relational-query-v3.md` 与 `use-query-v4.md`；没有定义的引用依然未知，不以零代替。Job 的批次仅为暂定结果，须读取 EOS 并检查终态。

v17 可通过现有 JNI `queryGraph` / `startGraphJob` 原始 JSON 入口调用；限定无显式 scope 且仅 method body 三类 demand，其余组合拒绝。JNI 将范围保持为不完整并复制静态见证；其余 JNI 入口仍拒绝 v17。固定 DEX 的静态测试不能证明完整 Q05、DEX verifier、ClassLoader、Android/ART 或业务运行。
