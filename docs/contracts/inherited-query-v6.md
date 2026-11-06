# 继承字段查询 v6

`declares_fields` 可选 `scope`：省略或 `declared` 保持原自身声明语义；`inherited` 在所选的静态来源范围中沿 superclass 候选路径统计祖先声明字段，自身只参与遮蔽。显式声明使用与原查询相同的 QueryID；继承查询使用 `query:v6`、profile `dex-query-inherited-v6`、capability 16384。v5 的 8192 位留给 BoundedExpand。显式请求 inherited_fields 能力即使没有谓词也进入 v6；直接实体根和关系表达式中的 Scan/Filter 可使用该条件。与 v7 数值或 v9 use_streaming 混用时遵循 [v10 组合契约](composite-query-v10.md)；与 v8 接口能力混用仍为 Unsupported。v5 BoundedExpand 尚未开放。完整 Q08 仍未完成。

关系表达式中，Scan 的继承解析域是该 Scan 与顶层 scope 的交集；Filter 的解析域是其输入子树所有 Scan 各自选择来源的有序并集。其他不属于该子树的来源不能参与解析，即使它们属于最终 query_scope。范围完整性沿用输入子树的来源完整性规则；显式 scope 可在不完整 Snapshot 中定义封闭子域。范围在首次实际求值且 owner 已知时才惰性准备，失败/取消不会发布部分范围。原 v6 已成功的直接查询编码与语义不变。

关系图可将基础 use 关系与 v6 继承谓词通过 `caller` 或 `target_ref` 组合；use 根仍使用 tagged 值与 v2 关系见证，继承节点保留其独立的 v6 路径证据。查找祖先只能使用该继承谓词所在子树的来源范围。外部 method_ref 的 owner 在该引用所属 DEX 中没有本地定义时仍为 Unknown，即使其他来源有同名定义，也不默认为已绑定 owner。

根对象是所在 DEX 的本地 owner class definition；无本地 owner 是 Unknown。根据父类描述符在当前查询所选来源范围搜索所有 class definitions；不合并重复 occurrence，不按扫描顺序猜测运行时绑定。每个候选定义是独立分支。完整路径已知且分支条件全部一致时才得出稳定结论；分支不一致、未定义的父类、范围不完整、环、条件无法定界时为 Unknown。不同分支一致的已知结论只表示静态候选下的结论，并非 ClassLoader 的解析结果。

只在这一有限静态模型中：根类自身字段不计入继承，较近类同名声明遮蔽较远祖先；排除祖先 private 字段，公共/受保护字段计为已知，包可见字段因 runtime package/loader 不明计为未知。字段类型、访问标志与 name/owner/type matcher 均基于定义 DEX 的原始表。此模型目前不解释接口边：任何接口路径都会导致相关结论保守 Unknown（恒真空约束除外）；非法访问位或环同样保守处理。此定义不是 Java `Class.getFields()`、DEX 完整校验或 runtime binding。`min`/`max` 的上下界采用已知与可能数量的三值判定，不将未知当成零。

路径枚举、中间候选、文字比较与匹配使用当前查询的 `max_work` 和 scratch PMR；路径/候选/证据分别受当前 `max_intermediate_rows` 上限约束。取消由同一查询检查器处理。不会对同字节不同 occurrence 合并结果。

## 版本化证据

保留原 `dmg_witness` 布局。新增 `DMG_WITNESS_INHERITED` 和精确结构尺寸验证的 `dmg_result_get_inherited_witness`；`node_id` 绑定叶谓词，`matched` 是叶在 NOT 之前的结果，`source_index/relation/local_index` 指向 Snapshot 的 class definition 或 field definition。结果与 Batch 保持来源和证据所有权。

同一个叶的 path/branch 下标局部有效，UINT32_MAX 表示无下标。`item_kind`：0 owner未知；1 path（`path_index` 为路径下标，`aux` 为父路径，`detail` 为 root/单候选/多候选枚举）；2 end（`path_index` 为终止路径，`branch_index` 为结束下标，`aux` 为 no-superclass/missing/incomplete/cycle 枚举）；3 branch（`branch_index` 同 end，`aux` 为已知匹配数，`detail` bit 0 为不完整、其余为内部三值）；4 field（`branch_index`、`path_index` 关联终止分支与祖先路径，实体指向匹配的 field definition）。调用方可用 Snapshot 来源和原始字段自行复核。旧 witness getter 对新 kind 给出普通共同字段；要解读祖先路径须调用新增 getter，不能将通用 reference_index 当作完整证明。

此草稿需要真实多 DEX 的覆盖/伪造反例、规范化 ID、布尔短路、未知上界、错误优先级、source scope、预算/取消/OOM、批次及 ABI 生命周期验证。接口图、多定义、路径爆炸和 runtime 验证尚须完成。现有静态测试不能宣称 ART 或 Q08 的全部能力完成。
