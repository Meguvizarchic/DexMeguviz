# 多来源 Snapshot 与身份契约

本版公开profile为`dex-method-metadata-v1`，对应C ABI的`dmg_snapshot_open_sources`。旧同步单DEX入口继续可用，内部同样构造Dataset。身份格式明确升级为Occurrence v2与Snapshot v2；尚无已发布持久格式需要兼容。

## 输入与原子发布

调用方提供有序`dmg_source_spec[]`，最多64项；每项有唯一非空slot_key、role、RAW_DEX/APK/AUTO、allow_no_dex、可选expected_sha256。所有字节在调用返回前已复制或转入核心拥有的已验证解压输出；输入buffer随后可释放。source namespace与slot/role按传入字节处理，CLI使用UTF-8。NUL由C字符串边界决定，字段不做Unicode规范化。

每项APK选择根目录`classes.dex`及`classesN.dex`（N>=2且无前导零）；按数字N排序，仍保留原中央目录index。普通其他资产不视为静态DEX。`classes1.dex/classes01.dex/classes0.dex`等数值近似名明确拒绝。重复完整ZIP名称拒绝。输入顺序先于每个APK的DEX顺序。

普通代码输入无DEX会失败；resource-only输入必须显式allow_no_dex，仍保留输入身份。任意成员损坏、摘要不符、超预算或未支持时，不发布任何部分Snapshot。同步open的失败不是空关系。

## 身份编码

`frame(x)`为`十进制字节长度 + ':' + 原始字节`。CLI字符串按UTF-8编码，所有摘要为小写SHA-256，未采用隐式字符串拼接前缀作为类型隔离。

- DEX ContentId：`sha256:raw-dex:v1:<完整字节长度>:<摘要>`。
- APK Input ContentId：`sha256:apk:v1:<完整APK字节长度>:<摘要>`。
- LogicalDexId：`logical-dex:v1:` + frame(DEX ContentId) + `header-offset:0`。当前稳定格式每容器一个逻辑DEX；稳定入口不启用041，独立实验入口见 [dex041-experimental-v1](dex041-experimental-v1.md)。
- Occurrence摘要输入：`dmg:occurrence:v2:` + frame(namespace) + frame(`raw-input`或`archive-entry`) + frame(原始input slot) + frame(role) + frame(entry_name，raw为空) + frame(DEX ContentId)。输出`occurrence:v2:<摘要>`。
- Snapshot摘要输入：`dmg:snapshot:source-set-v1:` + frame(namespace) + frame(`complete`或`incomplete`) + frame(input_count十进制)；依次对每个输入加入frame(slot)、frame(role)、frame(实际format数字1或2)、frame(allow_no_dex的0或1)、frame(Input ContentId)；再加入frame(source_count十进制)及每个有序Occurrence的frame。输出`snapshot:v2:<摘要>`。

Occurrence不包含Snapshot，不存在身份循环。同字节不同slot保留不同Occurrence。稳定slot换序时Occurrence保持，Snapshot改变。仅ZIP包装改变且相同slot/role/entry内DEX未变时，逻辑DEX与Occurrence可保持，而输入及Snapshot身份改变。资源包变化也改变Snapshot。

曾发现把APK的slot与entry编码成普通字符串后可与用户可控raw slot碰撞；v2用独立类型和字段隔离修复，保留C API攻击反例与独立Python重算测试。

## 候选与覆盖

`source_index`是展开后逻辑DEX序号，`input_index`是输入槽序号，`archive_entry_index`仍为中央目录序号。MethodRef索引只在LogicalDexId内有效。定义身份由Occurrence、LogicalDexId及声明位置组成，不能按descriptor或SHA去重。Result/Batch的origin getter返回对应来源；旧单源getter在逻辑DEX数不是1时返回Unsupported。

`scope_complete=false`表示调用者明确声明缺源。即使所有已给输入均遍历完，coverage仍Partial；Unique零/一个、Exists零均Undetermined/SourceScopeIncomplete。两个接受候选可以证明Ambiguous，一个Exists witness可证明存在。正常完成生命周期不等同完整来源覆盖。

## 所有权、成本与验证层

归档CRC/实际长度及头一致性通过后，Entry自有DEX字节；不再需要的压缩副本在构建元数据前释放。Dataset保留DEX字节与Facts，Result/Batch仍保持Dataset，适合当前驻留分析实现。嵌入式定位的一次一DEX释放策略尚未完成，不把本版驻留内存作为移动端验收。

Facts拥有字符串/类型/原型/引用目录，Method文本是这些稳定目录的只读视图；Facts仅允许移动，跨PMR resource的move assignment拒绝。输出行另行复制并计入result预算。原始调用方输入缓冲与Engine预算分别报告，不宣称RSS受同一限额控制。

APK输入摘要、ZIP CRC、MetadataSubsetChecked、指令检查、完整ART验证及运行时绑定是独立层。真实APK元数据通过只证明该scope，不能宣称BIL33、Hook、设备或性能通过。
