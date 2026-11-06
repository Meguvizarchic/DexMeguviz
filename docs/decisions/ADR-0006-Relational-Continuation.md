# ADR-0006 关系执行链的下一阶段边界

状态：实施方案；本文不代表算子已实现。

依据：工程包计划第6节及P1-08/P2-01验收。原资料用作需求来源，不引入额外外部操作授权。已实现七类根的契约见entity-query-v2.md。

当前Candidate只有主实体；Unique按返回行数早停。接入bag Union或一对多Join前，必须扩展类型化绑定/角色/路径，并把Unique声明身份与输出行数分开，否则同一实体两条关联会被错误判为歧义。P1-08先完成标量语义，P2-01再做优化/批量共享与差分。

建议按依赖顺序实施：

1. 输出行保留主实体、命名或角色绑定、关联端点、组成员和路径证据。明确实体、调用点(caller+PC)、完整绑定元组、owner组的身份。增加算子级输入/输出计数与覆盖/停止原因，不能把DAG的scan计数直接相加当唯一实体计数。
2. Union/Distinct：先接受同schema输入；bag保留重复，set按显式完整身份去重。Unique按声明的definition/owner/tuple身份计数。不得按descriptor/文本/ContentId跨Occurrence去重，hash相同后仍需完整key比较。明确重复证据保留策略。
3. GroupByOwner：只接受method/field definitions，以真实ClassDef身份分组；保存成员角色与配对。不能利用class/type内部self目录形成owner组，不能跨来源同名owner拼组。min/max和角色约束完成前不发布接受组；第17个成员可能使max16条件失效。
4. 完整StringUse/InvokeSite/FieldUse关系与Join/SemiJoin：现有谓词只找首见证，不是完整边关系。Join保留左右端点及多对多乘法，SemiJoin不让右侧重复放大左侧bag。local key必须带来源和类型；跨DEX使用完整SymbolKey并保留多定义。不存在右侧可靠见证且右侧未完成时，不得证明无匹配。
5. BoundedExpand：显式边类型、方向、scope、depth0语义、遍历/输出过滤、歧义/循环策略与端点集或路径bag。首版可仅选择普通invoke边；polymorphic/call_site不冒充普通callee。查询max_depth是语义边界；访问/边/路径/内存资源限额耗尽必须Partial/失败。每跳保留caller、PC、ref、解析目标及来源。

优先固定以下独立fixture断言：

| 输入 | 必须满足的结果 |
|---|---|
| 两分支命中同定义 | bag 2行、set 1行、Unique definition仍仅1个身份 |
| 相同字节两个Occurrence | set仍保留两个定义，Unique definition为Ambiguous |
| 左bag2行、右3个匹配 | Join6行、SemiJoin2行；配对可追溯 |
| 同caller两个PC调用同目标 | 两个InvokeSite；callee集合可去重，路径bag不能丢PC |
| 一个owner两方法、另一来源同名owner | 分别为一组与两个独立owner组 |
| 两个owner分别满足角色A/B | 不得跨owner拼成A+B组；caller配对同理 |
| max16组第17个成员才出现 | 不得提前发布满足条件的Exists/Unique组 |
| 跨DEX B符号有两个定义并各自通向C | 保留所有分支或明确歧义，不选首个定义（Q07） |
| A→B→A及通C菱形路径 | 深度边界终止，端点集合与路径bag分别验收 |
| 前32 raw候选被后续过滤，第33才接受 | 输出cap不能在残余/组条件前截断（Q10） |
| 后来源出现更优TopN | 全范围完成后才保证排名，tie带来源与身份 |
| scope/匹配模式/解析策略/profile不同 | QueryID和共享key区分，bag分支顺序不随意规范化（Q12） |
| 中途取消/分配失败/工作预算耗尽 | 不返回成功空关系，所有中间容器和证据计PMR并最终回收 |

正命中证据可局部复核，Unique/不存在仍需完整相关范围。C ABI/Job/CLI和独立证据须随算子同步推进；完整Q01–Q12、Android后验、BIL33、SQL与设备性能各自保留验收门槛。
