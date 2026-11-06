# 配套桌面命令 v1

`python -B tools/dexmeguviz.py`提供稳定路由：inspect/query/explain/sql显式使用命令前的--native可执行文件；diff/verify/precompute使用随项目固定的Python工具。不会从PATH猜测native、调用shell或执行包内代码。脚本类命令使用自己的参数，例如diff的--exe；同时传两类backend配置会拒绝。--describe只显示分派argv而不执行backend。

```text
python -B tools/dexmeguviz.py --native PATH_TO_EXE explain --query query.json
python -B tools/dexmeguviz.py diff --exe PATH_TO_EXE --before old.dex --after new.dex --workdir NEW_RUN_DIR
python -B tools/dexmeguviz.py verify --dex input.dex --result result.json --query query.json
python -B tools/dexmeguviz.py precompute consume --package pack.bin --expected receipt.json --current sources.json
```

路由转发原backend退出码，不把0解释为生产业务验收。native沿用0/2/3/4，diff沿用0/2，受限verify为0成功、2不支持/无效、3预算；precompute沿用自己的合同。Ctrl-C返回130。Windows native路径必须是明确.exe；二进制与安装目录应由调用方信任，文件路径本身不是认证。

差分算法与判定不变。新增--workdir要求全新目录并拒绝观察到的reparse点，保留before/after每类扫描query、stdout/stderr和命令记录，不自动清理。未提供时原TemporaryDirectory行为保持；--output仍沿用原子发布合同。保留日志不意味着全部资料可直接公开发布。

verify新入口把现有独立metadata oracle包装为有界命令：DEX≤64MiB、result≤8MiB、query≤64KiB，严格JSON键/数字/结构，原 `--dex` 模式只接单来源method_defs的name/owner exact或contains、raw flags_contains和enumerate/exists/unique；`--sources` 的有界多来源支持范围见下文。不支持的scope/order/body/关系等形状明确拒绝，不静默忽略。数字/文本candidate字段先检查类型，再由旧独立解析器核对原始字节和该有限查询语义；无native CLI调用。

成功状态为MetadataEvidenceVerified，同时返回producer执行状态、独立范围，并明确query_identity_verified=false、runtime_binding=NotPerformed。它不认证QueryID、加载来源或ART，也不支持所有现有profile；原verify.py及专用验证器仍保留。输入失败或部分coverage不会被提升成生产成功。

本轮只做配套路由、一个有限metadata正例/unsupported反例、同输入差分及12份扫描日志保留的连通检查。完整差分/所有证据/CI和跨平台验收待统一阶段。

## 有界 raw/APK SourceSet 核验

`verify --sources expected-sources.json --result result.json --query query.json` 把已有 multisource 独立元数据核验接入配套命令，支持显式RawDex和受限Apk输入。`--sources` 与原 `--dex` 互斥；原单 DEX 入口的准入和核验范围保持不变。新入口不调用 native 或执行输入指定的代码。

来源清单必须由调用方独立提供，不能从待验结果的 inputs/sources 反推。格式为：

```json
{"schema_version":1,"namespace":"cli-v1","scope_complete":true,"inputs":[{"path":"first.dex","format":"RawDex","slot_key":"first","role":"base"},{"path":"second.dex","format":"RawDex","slot_key":"second","role":"code-split"}]}
```

例如APK与资源分片组合可使用：

```json
{"schema_version":1,"namespace":"cli-v1","scope_complete":false,"inputs":[{"path":"base.apk","format":"Apk","slot_key":"base","role":"base"},{"path":"resources.apk","format":"Apk","slot_key":"resources","role":"resource-split","allow_no_dex":true}]}
```

每项可以额外提供 `expected_sha256`（小写 SHA-256）；未知键拒绝。相对路径以独立清单目录为基准，只从这份清单读取文件。slot 必须非空且互异；首项必须是含DEX的base，后续为code-split或resource-split；resource-split必须为Apk并显式 `allow_no_dex: true`，其余输入不得启用此选项。同一路径或同字节可以用不同 slot 重复出现，身份和候选仍按 occurrence 区分。namespace、slot、role 必须是无 NUL 的有效 UTF-8，分别最多 1024 字节；路径最多 4096 UTF-8 字节。

范围限定为1–8个显式raw或APK输入、至多16个展开DEX；单输入/单DEX最多16 MiB，输入总量及展开DEX总量各最多64 MiB。DEX支持035/037/038/039/040，AUTO、DEX041、反向字节序不在本入口内。APK仅支持单盘、普通非ZIP64目录、无data descriptor、无加密且stored/deflate的已选DEX；目录最多4096条/4 MiB、条目名总计1 MiB，每APK所选压缩数据累计不超过64 MiB。只选择根目录标准classes.dex/classesN.dex，数值顺序展开并保留中央目录索引；重复名称、非规范数值名、局部头及长度/CRC不符、DEFLATE流末端不符均拒绝。非选择的普通资产不会被解压。ZIP64、描述符或其他压缩特性保守拒绝，不表示这些是非法APK。清单和 query 各最多 64 KiB，result 最多 8 MiB；沿用严格 JSON 类型/重复键/结构上限。元数据解析前执行资源预检：单表与单 class_data 列表最多 100000 项、单字符串最多 4096 UTF-16 单元、原型最多 1024 参数且物化最多 16384 单元。累计表项、字符串/原型物化量、重复引用的 class_data/code 范围和匹配成本按固定上界计费，总额 4000000；字符串查询 pattern 最多 256 UTF-16 单元。超额返回 BudgetExceeded/退出3；这些是 verifier 的预检额度，不是 native work、CPU 时间或进程 RSS 指标。

仍只接受 method_defs、name/owner 的 exact 或 contains、raw flags_contains，以及 enumerate/exists/unique；查询中的 scope/order/body/关系和其它字段明确拒绝。新入口仅核验 execution_status=Complete 的 `dex-query-method-v1` 静态结果；生产者预算失败、取消或其它执行状态保守返回 Unsupported。结果可因调用方声明范围不完整而为 Partial，不能据此宣称唯一或不存在。

先核对数字/布尔等 JSON 类型，再由既有独立解析器重新读取元数据；复用 multisource 的带长度帧 content/occurrence/logical/snapshot 身份和有限查询证据规则。新入口只检查其声明子集的APK目录与所选DEX，不认证APK签名、不验证未选资源内容；不解码指令、不使用原生缓存，也不核验输出诊断、QueryID 或默认候选排序。成功仍叫 MetadataEvidenceVerified，query_identity_verified=false、runtime_binding=NotPerformed。scope 内的 `declared_scope_decision_verified` 仅在独立有限集合/见证支持 ProvenTrue 或 ProvenFalse 时为 true；Undetermined 和 NotApplicable 不升级为已证明决策。

`source_scope_claim` 明确记录 caller_declared_complete 或 caller_declared_incomplete，`source_scope_authenticated=false` 始终保留。complete 是调用方的来源闭包声明，工具只核对该声明所列有序raw/APK文件及相关静态证据，不认证设备安装集合、加载来源或 ClassLoader 完整性。此增量不代表全 QueryIR 或完整 P2-08 验收。
