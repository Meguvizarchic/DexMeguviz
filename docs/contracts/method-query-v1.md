# 方法根 QueryIR v1

字符串方法根公开profile为`dex-query-method-v1`。新增六类实体根及三值属性见`entity-query-v2.md`；对象关系表达式、Union/Distinct、GroupByOwner及四种键的Join/SemiJoin见`relational-query-v3.md`。完整使用关系与BoundedExpand尚未完成，P1-08继续进行中。未知字段/必需能力直接Unsupported，不会忽略后返回空集。

## 统一入口

C ABI通过`dmg_query_compile_json`生成不可变Query；CLI也调用此入口，已移除自己的谓词翻译器。`dmg_query_execute`同步执行，Job复用同一Plan。旧`dmg_query_compile_methods`和`dmg_query_methods`被翻译为同一typed plan，不保留另一套查询语义。

```json
{
  "schema_version": 1,
  "relation": "method_defs",
  "where": {
    "return_type": "I",
    "parameters": [],
    "using_strings": {"all": [{"op": "exact", "value": "quality settings:"}]}
  },
  "intent": "unique",
  "max_results": 2,
  "evidence_profile": "minimal"
}
```

编译输入最多64KiB，JSON嵌套最多32层、16384值节点；typed predicate最多1024节点、256文本matcher，scope最多64个input slot。持久Plan与临时JSON树分别使用Engine query/scratch PMR，输入返回后可改写或释放。

## 谓词

`where`可以是布尔值或对象。对象的各字段为AND；`all:[...]`、`any:[...]`、`not:{...}`显式组合。All空数组为true，Any空数组为false。纯元数据条件先于需要指令的条件；未知能力在编译时统一拒绝，不能藏在短路分支中。

文本可写为字符串（Exact简写）或`{op:exact|contains|prefix, value:字符串}`；`value`与`u16:[0..65535]`二选一。默认按UTF-16 code unit比较，不做Unicode规范化；`ascii_case_insensitive:true`只折叠A-Z。Contains使用线性KMP，支持取消/工作配额。

`using_strings` 中不折叠的Exact条件先通过UTF-16有序字符串表做精确查找；每个比较单元继续计入工作量并遵循原取消检查，查找结果在当前来源求值器内按matcher缓存。字符串存在于池中不等于方法使用该字符串，仍需检查方法指令；未命中可形成限定于当前来源的`string_pool_absence`证据。

| 字段 | 语义 |
|---|---|
| name / owner / prototype / return_type | 对实际声明文本或签名做文本谓词 |
| param_count | 整数为精确值，或包含min/max的闭区间 |
| parameters | 有序完整参数类型matcher数组，同时要求参数数量相等 |
| parameter | `{index, type}`，仅约束指定参数；越界为false |
| flags_contains / flags_exact / flags_any | raw DEX flags；Contains是全部required位满足 |
| flags / owner_flags | `{mode,value,domain:"dex"}`；owner_flags作用于声明类；reflection域尚未实现 |
| kind | constructor、clinit、normal；不把构造器结果伪装为运行时Method绑定 |
| superclass / direct_interface | 仅直接父类/直接接口，未隐式遍历继承树 |
| using_strings | `{all:[文本matcher...]}`或`{any:[...]}`，只看方法const-string/jumbo事实 |
| invokes | all/any目标matcher；每个条件独立存在性，允许同一callsite满足重叠条件 |
| field_access | all/any字段引用matcher，可指定access为read/write/any |
| declares_fields | `{where:{owner?,name?,type?,flags_contains?},min?,max?}` 默认只统计当前owner自身声明字段；显式 `scope:inherited` 使用独立的[inherited-query-v6](inherited-query-v6.md)静态模型 |

Invoke目标支持owner/name/prototype/return_type/param_count/parameters，signature指**被引用method_id的签名**；polymorphic的extra proto单独保留，不冒充该签名。reference_kind可为method_like、method、method_and_proto、call_site。call_site只支持种类筛选；bootstrap符号谓词明确Unsupported。引用目标的未知定义属性不当作flags=0，未提供这类修饰符谓词。

方法无body时没有DEX指令使用；字符串只出现在pool、注解或静态值，不算方法StringUse。Exact字面量不在完整string pool时，可用元数据排除该来源的方法；否则按需求检查方法体。一个方法在一个查询中最多解码一次，需求取该计划的string/invoke/field位闭包；不建立反向callers索引。

## 作用域、集合、排序、投影

默认在Snapshot全部已声明来源中搜索，继承Snapshot的scope_complete。`scope:{slots:[...]}`选择明确存在的input slots，成员选择是集合，仍按Snapshot顺序遍历；缺slot为SourceMismatch。显式已知子范围可完整，即使父Snapshot声明缺源。空slots是显式空范围，不等于all。输出query_scope与Snapshot的scope_complete分别保留。

此方法根的`semantics:set|bag`作用于天然唯一的method_defs scan/filter，两者无重复差异；对象关系的bag Join/Union范围见`relational-query-v3.md`。

`order_by:[{field,direction}]`支持owner/name/prototype/flags/source_index/method_index，direction为asc或desc。文本排序仍为UTF-16单位；相同排序键以source_index与definition ordinal稳定打破平局。

`intent`为enumerate、exists、unique、top_n。Exists可在一个可靠见证后停止；Unique可在两个不同定义后证明Ambiguous；一个或零候选需要完整范围才能做唯一/无匹配结论。TopN使用有界heap但遍历整个相关范围，后分片的更优候选不会遗漏；缺源时decision为Undetermined且order_verified=false。TopN的ProvenTrue表示完整全局排名成立，不表示结果非空。

max_results是1..100000的结果额度。Enumerate/Unique因额度停止返回BudgetExceeded/Partial，不把LIMIT1当唯一证明。TopN把该值解释为N。max_work默认100000000，涵盖定义/谓词、文本、排序及已完成decoder验证工作；失败时profile计数是已记录工作，不伪称失败路径的每个机器指令成本。

projection选择owner/name/prototype文本；identity和最小evidence始终保留。未投影文本不物化，C getter长度为0且projection_mask明确标记；JSON省略字段，不伪造空名称。

## 规范化、证据与生命周期

QueryID为`query:v1:SHA256`。规范化使用显式小端u32/u64、带长度字节串与UTF-16单位；包括intent、额度、工作预算、投影、set/bag、scope、能力与排序。对象字段序、文本value/u16及支持的别名统一；纯All/Any子树按无符号字节canonical key排序。SourceSet顺序不在这里重排。

稳定node_id按规范化树遍历编号，避免相同QueryID的等价输入产生无法对应的证据编号。并未宣称完整布尔代数等价化。

证据包含metadata、string_use、invoke、field_use、instruction_scope、no_body或string_pool_absence；正指令见证保留PC、opcode、引用域、index与extra proto。否定只从已完成的相关事实或元数据不可能性证明得到；corrupt/unsupported/cancel/budget不能变成“不含”。

当前标量参考路径先完成受预算控制的候选集合/TopN形状，再物化和发布Batch。所有Batch为provisional，必须读Job最终状态。Plan由Result/Batch共同保活；scope、QueryID和证据在释放Query/Job后仍有效。该路径不等于P2的优化多规则计划或EmbeddedLocate低峰值执行。

## 本轮验证范围

独立编译和标量测试、真实C JSON消费者、CLI原始PC核对、等价QueryID/见证、跨来源和后分片TopN、缺源、预算/取消及损坏否定均已运行。固定9.17 APK的PLAYER_DEFAULT_QUALITY静态例得到`Ltz1/h;->a()I`、PC32；独立Python重扫相关2029方法体并重算QueryID确认唯一。仍未进行ClassLoader、Hook、BIL业务缓存或性能验收。
