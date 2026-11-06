# QueryIR v1 与启动子集

完整QueryIR v1的能力范围遵循工程计划第6节；当前已扩展为方法根及六类非方法实体根，现行详细契约见[method-query-v1.md](method-query-v1.md)与[entity-query-v2.md](entity-query-v2.md)。以下保留早期元数据语法示例。未支持字段/关系/操作返回Unsupported，不当空关系或忽略过滤条件。

```json
{
  "schema_version": 1,
  "relation": "method_defs",
  "where": {
    "name": {"op": "exact", "value": "locate"},
    "owner": {"op": "exact", "value": "Lsample/Example;"},
    "flags_contains": 1024
  },
  "intent": "unique",
  "max_results": 4096
}
```

`where` 条件用 AND；name 允许 exact/contains，owner 仅 exact。文本在边界变为 UTF-16 code units，无隐式 Unicode 规范化/大小写折叠。`value` 与 `u16:[0..65535]` 二选一；u16 可表达孤立代理项和 NUL。原始 MUTF-8 不作为普通文本比较域。空 Contains 模式匹配所有名称。

flags_contains 在 **raw DEX access_flags** 域采用 `(value & required)==required`；0 不限制。与 Java reflection flags 不做隐式转换，未知属性不替代为零。

relation只包括所选Snapshot的方法定义；未定义外部引用、字符串池值与方法体使用字符串均不是该关系。支持有序多来源，局部ID不隐式跨DEX解析。行身份由Occurrence和定义位置组成，遍历顺序为input、APK数字DEX顺序、class_def、direct/virtual方法；不是全局TopN排序。来源缺口由SourceSet scope_complete显式传递。

intent 允许 enumerate（默认）、exists、unique。max_results 默认 4096，必须 1..100000；它是输出候选上限，不能改变唯一性逻辑。已完成而只有一个命中可证明唯一，达到两个不同定义可证明歧义；只有一个后遇限额则 Undetermined。

JSON 输入 <=64 KiB、深度<=32、节点<=16384；拒绝重复键、非法UTF-8、整数溢出、非预期类型及尾随字节。未知 schema version/能力拒绝。

JSON计划编译、规范化QueryID、required capabilities、All/Any/Not、slot scope、投影/排序/TopN已接入共享核心。类/字段/ref/type/string根、Union/Distinct、GroupByOwner及四种键的Join/SemiJoin已加入，详见relational-query-v3.md；完整使用关系和有界展开继续实施，不能宣称全部Q01–Q12或BIL33已验收。
