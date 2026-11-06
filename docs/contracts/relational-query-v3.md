# 基础关系查询 v3

JSON仍使用schema_version=1；relation既可保留原字符串，也可使用对象表达式。字符串入口保持原v1/v2 QueryID与输出；对象入口使用query:v3与dex-query-relational-v3，包括最终输出仍为method_defs的对象查询。当前实现四种显式键的Join/SemiJoin；完整StringUse/InvokeSite关系和BoundedExpand尚未实现。

## 类型与算子

| op | 参数 | 语义 |
|---|---|---|
| scan | relation字符串；where?；scope? | 七类实体根，谓词沿用typed属性规则 |
| filter | input；where | 对输入主实体过滤，保留绑定和原始叶证据 |
| union | 非空inputs；semantics=bag或set；identity? | 同类型输入；bag保留分支重复，set按entity或tuple去重 |
| distinct | input；identity? | entity忽略角色绑定，tuple包含全部绑定；默认tuple |
| label | input；label | 给主实体附加角色，名称为ASCII字母/数字/下划线/点/短横线，1–64字符 |
| group_by_owner | 非空inputs；min?；max?；required_roles?；role_policy? | 输入仅method_defs/field_defs，可混合；输出真实owner ClassDef |
| join | left；right；on | 按指定键连接，输出left主实体并保留左右绑定；bag多对多保留全部配对 |
| semi_join | left；right；on | 右侧存在匹配时保留left行与左侧bag重数；右侧重复不放大结果 |

Union不接受异构主实体类型；Group允许方法与字段来自不同输入。Group按不同成员EntityKey计数，默认min=1、max=UINT32_MAX，重复bag行不增加人数。role_policy默认shared，允许同成员满足多个角色；distinct要求不同成员，通过匹配分配而非贪心首选。重复required_roles拒绝。空输入不生成零成员组，min=0也只过滤已出现的owner组。

```json
{
  "schema_version": 1,
  "relation": {
    "op": "group_by_owner",
    "inputs": [
      {"op":"label","label":"field","input":{"op":"scan","relation":"field_defs","where":{"owner":"Lcatalog/Child;","name":"shared"}}},
      {"op":"label","label":"method","input":{"op":"scan","relation":"method_defs","where":{"name":"abstractMethod"}}}
    ],
    "min":2,"max":2,"required_roles":["field","method"],"role_policy":"distinct"
  },
  "intent":"unique"
}
```

Group以来源Occurrence及本地ClassDef身份分组，不按descriptor跨来源拼接。每个成员总有无标签绑定，并叠加全部角色绑定；绑定按路径、角色文本和实体键排序、完全重复绑定去重。叶见证保留实际成员的source/relation/local_index与产生见证的算子节点，不能用组ClassDef偏移解释成员PC。

实体身份为具体来源、relation、local_index；tuple身份为主实体加完整规范化绑定，其中每个绑定包含左右路径、角色和实体键。绑定按路径、角色文本和实体键排序并去除完全重复项。Join算子节点号、links、proof_bindings和叶见证属于证据，不参加tuple身份；不同节点产生相同tuple时可按tuple合并。Distinct保留首个True代表；只有Unknown时保留首个Unknown。同实体不同角色在entity去重时只保留代表，不隐式合并角色；tuple去重保留不同角色或路径行。Union保留分支顺序，不按名称、hash或字节内容合并Occurrence。

### Join与SemiJoin键

`on`必填，只有以下四种键；不适用的左右类型在编译期Unsupported，左右子表达式顺序保留。输出主实体类型继承left；top-level `semantics=set`仍可对最终tuple去重。

| on | 允许的类型与比较 |
|---|---|
| same_entity | 左右relation相同；来源Occurrence、relation、本地序号全部相等 |
| local_definition | method_defs↔method_refs、field_defs↔field_refs或class_defs↔type_refs；必须同一来源Occurrence且引用表ID相同 |
| local_owner | left为方法/字段定义或引用，right为class_defs；必须同一来源Occurrence且成员的owner type ID等于类type ID |
| symbol | 左右均属于同一类：方法定义/引用、字段定义/引用、类定义/类型引用、或两个字符串值。按完整UTF-16 code units精确比较；方法为owner+name+prototype，字段为owner+name+type，类型为descriptor，字符串为value |

symbol允许跨来源匹配，保留全部匹配组合；它不执行ClassLoader选择、运行时分派或跨DEX单一绑定。local_definition表达同DEX定义与引用对应，不把外部引用补成定义。left有m条、right有n条满足键时Join保留m×n条；SemiJoin对每条left只判断是否存在右侧匹配，因此保留left原有重数。右侧尚不完整且没有确认匹配时，SemiJoin不能把该left当成确定不匹配。

```json
{
  "schema_version":1,
  "relation":{
    "op":"join","on":"local_owner",
    "left":{"op":"scan","relation":"method_defs","where":{"owner":"Lcatalog/Child;"}},
    "right":{"op":"scan","relation":"class_defs","where":{"descriptor":"Lcatalog/Child;"}}
  }
}
```

每个Join将left和right当前实体与其既有绑定分别加上L或R路径前缀；嵌套时路径从外层向内层排列。SemiJoin保留左tuple身份，但将右侧匹配实体及其绑定存入proof_bindings：右侧证明以R开头，已有左侧嵌套证明以L开头。`links`记录连接节点、键和左右实体端点；证明绑定保留产生它的SemiJoin节点和角色。证明信息与结果绑定分别保留，不能把proof_bindings计入tuple身份或推断右侧不存在。

## 作用域、Unknown、结果意图

顶层scope与Scan scope求交，两处显式slot都验证存在；缺失为SourceMismatch。显式已知Scan范围可以在不完整父Snapshot中完成。query_scope.sources是所有被选择来源的有序并集；是否范围完整与属性Unknown分开。

继承字段谓词使用 v6 规范化域。Scan 内的祖先解析只使用该 Scan 与顶层 scope 的交集；Filter 内的祖先解析使用其输入子树所有 Scan 所选来源的有序并集，而不是整个关系图无关分支的并集。只在实际执行该谓词且 owner 已知时准备解析范围；详细限制和静态候选定义见 inherited-query-v6.md。

Unknown行在中间关系中保留；Filter False可删除，True保留其未知状态；Set/Distinct的同身份True覆盖Unknown。只输出最终True行。根unknown_rows是最终未知行数；Unique先按unique_by去重，因此该意图下统计未知身份数。分组对仍不确定的成员保守判断，不能提前把可能被后续成员推翻的组作为可靠见证。

来源范围不完整时，即使当前已有匹配成员，后续缺失的Join结果仍可能改变同owner组的成员数、上限或角色条件；当前GroupByOwner对所有已出现的owner候选组保守标记Unknown，不把它们发布为True。这包括部分实际上不受缺失来源影响的本地组，因而可能降低确定性。执行中记录到来源缺口导致的Unknown且最终来源范围不完整时，结果reason可为SourceScopeIncomplete；普通不可得属性可报告UnknownAttribute。来源未知标记是执行级诊断，多个未知原因混合时，reason不是逐候选的完整因果证明。无候选的Exists/Unique仍为Undetermined；已确认的可靠存在见证可证明Exists为True。

对象查询默认保留表达式自身的bag/set语义；顶层显式semantics=set生成最外Distinct(tuple)。顶层where生成最外Filter，随后才做该Distinct。

unique_by默认entity，可设tuple。Unique输出最多两个不同身份代表，不用重复bag行消耗唯一性额度。max_results=1遇第二个不同身份仍为ResultLimit/Partial/Undetermined；不能用被截断的一行证明唯一。Exists取一个可靠结果；TopN对完整中间关系排序后取前N。所有根结果限制均在关系处理后应用，成员数量/角色条件完成前不发布接受组。

## 预算与profile

关系节点最多128，最终树深最多32，JSON/谓词/文本预算沿用原规则。max_intermediate_rows默认100000，可设1..1000000；它约束实际物化的中间行数，包括合并后去重前的输入。受限参考实现会先物化中间关系，内存全部走Engine scratch PMR。该上限、内存预算或max_work耗尽为失败，不返回成功空关系。未来优化不能改变最终语义。

CLI关系结果的visited_rows/total_rows是各Scan记录的总和，重复分支可能重复扫描；counter_domain固定scan_records，不代表不同实体数。relation_profile包含：

- root_node、unique_by、identity_count（完整结果中所有根True行按unique_by去重后的身份数，不受输出cap影响）。流式中断时 identity_count 仅是已观察到的可靠根身份下界，可包含已形成但未成功交付的行；决策只依据已交付见证。
- 每算子的input_rows/output_rows/unknown_rows，其中output含内部Unknown行。
- Scan的visited_rows/total_rows；非Scan这两项为0。complete表示该算子处理结束且来源完整、输出无Unknown。

主结果coverage仍受根Unknown、来源范围、执行状态和输出截断约束；算子profile完成不等于最终枚举列表未被截断。当前没有优化索引或跨Scan事实共享的验收，不从计数推导性能收益。

## C ABI与保活

新增binding、binding path、proof binding、proof binding path、relation link、relation witness、graph info及operator profile getter；带out_size的输出结构检查准确尺寸，错误不写buffer。所有对象关系查询拒绝旧方法Result/Batch/Job状态接口，即使主输出是method_defs；通用relation接口可读。

绑定包含完整实体属性与文本；根projection仅控制主实体文本。Result/Batch自有绑定和证明绑定的文本、路径数组及有序links，保留Query标签与SourceSet，并持有独立profile副本；路径长度0合法，返回的借用视图至结果最后一次release前有效。原Engine/Snapshot/Query/Job句柄释放后仍可读取。Job EOF后必须检查最终status，BudgetExceeded/Cancelled不能由EOF抹去。失败Job可读取已记录的算子统计；queued阶段计数尚未建立。

## Canonical QueryID

对象域为ASCII DexMeguviz:QueryIR:relational-v3，无NUL。整数小端，bool为u32；frame是u64字节长度加内容。先写输出Relation u32、intent u32、max_results u32、max_work u64、projection/bag/explicit_scope/required_capabilities/unique_identity/max_intermediate_rows（各u32），随后scope数组与order数组（沿用v1/v2），再写根关系递归编码。

关系节点依次为op、输出Relation、predicate存在位（各u32）；存在时frame(原predicate编码)；label存在位，存在时frame(label文本)；minimum/maximum/identity/bag/explicit_scope/distinct_roles（各u32）。仅join/semi_join节点紧接着写join_key u32：same_entity=0、local_definition=1、local_owner=2、symbol=3。然后写scope数量及frame(slot)；required_roles数量及frame(label文本)，保留角色数组顺序；children数量及每个frame(递归子关系)，保留左右/分支顺序。物理索引、stable_id与标签intern索引不编码；原有无Join v3节点编码不增加字段。

最终为query:v3:+SHA-256。纯All/Any内部规范化沿用v1/v2；作用域slot排序，bag分支顺序不重排。关系能力位512，owner group位1024，join位2048；无Join且未显式要求该能力的旧v3计划编码保持不变。默认method Scan的独立字节golden为d3b9d916113de0403046db0ee9b5b4247591d5ccc2904e17809eadace97eff23；此独立hash覆盖范围仅该形状，其他树另有语义差异和别名对照。
