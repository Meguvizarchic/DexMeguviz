# 实体查询 v2

本阶段扩展已有typed QueryIR的根类型。JSON仍使用`schema_version:1`；字符串方法根保留`dex-query-method-v1`，其余六种字符串根使用`dex-query-entity-v2`。对象关系表达式及Union/Distinct/GroupByOwner/Join/SemiJoin的支持范围见`relational-query-v3.md`；BoundedExpand尚未实现。

## 根与属性

| relation | 本地序号 | 文本谓词/默认投影 | 定义属性 |
|---|---|---|---|
| method_defs | 解析后的声明目录序号 | name、owner、prototype及已有方法签名条件 | raw flags、定义偏移、code_offset已知；0表示无方法体 |
| class_defs | class_def表序号 | descriptor / type_descriptor | flags、class_def偏移已知 |
| field_defs | 声明目录序号 | name、owner、type / owner、name、type_descriptor | flags、encoded_field偏移已知 |
| method_refs | method_id | name、owner、prototype及方法签名条件 | 仅同DEX有定义时补充flags与定义偏移；不暴露代码 |
| field_refs | field_id | name、owner、type / owner、name、type_descriptor | 仅同DEX有定义时补充flags与定义偏移 |
| type_refs | type_id | descriptor / type_descriptor | 仅同DEX有class_def时补充flags与定义偏移 |
| string_values | string_id | value / string_value | 没有定义/flags/code属性 |

`local_index`与`reference_index`不同：定义目录顺序可能与ID表顺序不同。`record_offset`指向当前根自己的记录；引用根永远指ID表，定义根指class_def/encoded_field/encoded_method。`definition_offset`只在存在同DEX定义时可用。

实体身份由Snapshot的具体来源Occurrence、relation和local_index共同确定；同字节不同来源仍是不同实体。相同名称或描述符不合并来源。当前所有实体属性都是静态DEX目录属性，不宣称ClassLoader或运行时调度解析。

`has_local_definition`是已知的本地事实；不搜索其他DEX。即使另一来源包含同符号定义，本来源的引用仍保持无本地定义。引用的owner类在同DEX已定义时，可查询该owner的flags、直接父类、接口及自身声明字段；这不等于引用成员本身有定义。

方法体谓词using_strings/invokes/field_access仅用于method_defs；不适用的谓词、投影、排序字段在编译期Unsupported，包括空量化数组和布尔短路分支。类与type根的superclass/direct_interface及默认declares_fields作用于自身类目录，method/field根作用于声明owner；默认不含继承字段。显式继承范围另见[inherited-query-v6.md](inherited-query-v6.md)，与当前v2自身声明语义分开。`owner`与`owner_flags`仅用于成员，类不会成为自己的声明owner。

## 三值逻辑和完成度

缺少本地定义的flags以及缺少owner定义时的层次/声明字段属性为Unknown。

- NOT Unknown = Unknown。
- All中False决定False，否则任一Unknown使结果Unknown。
- Any中True决定True，否则任一Unknown使结果Unknown。
- `flags_contains:0`在未知flags上仍为Unknown。

只输出根谓词为True的行，根为Unknown的已访问行累计为`unknown_rows`。根被其他False/True分支决定的行不算Unknown。叶见证的`matched`是0/1/2（False/True/Unknown），记录包围它的NOT之前的结果；CLI将Unknown表示为null。

源范围完整性`query_scope.complete`与谓词已判定程度分开。扫描结束仍有Unknown时coverage为Partial，reason为UnknownAttribute，Unique/无匹配不得据此证明。但Exists的真实见证、Unique的两个不同真实候选仍能决定真/假。代码损坏、取消、预算耗尽仍是执行状态，不能归为普通Unknown。

例如：

```json
{"schema_version":1,"relation":"field_refs","where":{"has_local_definition":true,"not":{"flags_contains":8}},"intent":"enumerate"}
```

显式限制有本地定义使外部引用由False排除；直接删除该限制会保留外部引用的Unknown并降低完成度。

## 排序、投影与ABI

沿用已有scope、intent、max_results、max_work与UTF-16 matcher。排序支持适用于根的owner/name/prototype/descriptor或type/value/flags，以及source_index/local_index。method_index仅用于方法根，指method_id。NULL flags升序在前、降序在后；并列时按来源和本地序号稳定排序。排序NULL不等于过滤谓词Unknown；无过滤的引用枚举可以完整。

投影支持identity/evidence及适用的owner/name/prototype/descriptor或type/value。身份与证据始终保留。C ABI的`DMG_PROJECT_TYPE`映射type_descriptor、`DMG_PROJECT_VALUE`映射string_value。

新增`dmg_result_get_entity`、`dmg_result_get_relation_info`、`dmg_job_get_relation_status`、`dmg_job_wait_relation`，要求准确out_size，错误时不写输出。旧struct布局及DMG_ABI_VERSION保持；旧方法result/batch getter、旧job状态/wait对非方法根返回Unsupported。Batch就是Result，可用通用getter读取。新row文本视图由Result持有，Result/Batch保活SourceSet与Query，原Engine/Snapshot/Job句柄释放后仍有效。

通用结果使用visited_rows/total_rows，不伪装成方法数。Job在源范围解析前计数尚未建立；批次coverage固定Partial且decision不代表全Job，终态从relation status读取。unknown_rows是执行器已扫描范围的统计，批次中的值不是该批候选的未知数。

CLI成功方法结果保留旧字段；其他根有relation、visited_rows/total_rows/unknown_rows，候选包括local_index/reference_index/record_offset与可空属性。为兼容原失败输出，尚未取得typed结果的错误包仍使用旧profile；错误包没有成功实体/关系含义。

## QueryID

已有方法查询继续使用query:v1与原method-v1域，历史固定字面量查询哈希不变。新增根、新增has_local_definition或local_index等排序进入query:v2。域为ASCII `DexMeguviz:QueryIR:entity-v2`，随后先写relation u32，再沿用v1的intent u32、max_results u32、max_work u64、projection u32、bag u32、explicit_scope u32、required_capabilities u32、scope与order及canonical predicate树；整数小端，UTF-16与字节串有显式长度。relation枚举值与公共C枚举一致。非方法根要求的能力位为256（实体根）加原有metadata等位。

作用域slot排序和纯All/Any子树排序按无符号字节canonical顺序，稳定节点编号由canonical遍历产生。QueryID不含具体Dataset，数据绑定另由Snapshot/Occurrence身份承担。新无条件六根查询已有独立Python canonical哈希对照；不将该对照扩展宣称覆盖所有新谓词组合。
