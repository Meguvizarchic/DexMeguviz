# v14 Scan 与 Filter 链反射标志的独立见证复核

`tools/evidence_verifier/reflection_scan_v14.py` 复核单个完整 raw DEX 来源的 v14 单 Scan，或最多八层 Filter 包围一个 Scan 的链。每个 Filter 的条件必须是单个 `flags` 或 `owner_flags` reflection 叶；Scan 条件可以是默认/显式 `true` 或同类单叶。至少有一个 reflection 叶，只支持默认投影和工作参数、无排序/作用域的 Enumerate。除上述形状外的算子、布尔组合、多来源、不完整 scope、其他 intent、预算中断或结果截断均拒绝，不推断其结果。输入必须是可被现有独立 DEX 解析器识别的文件。

复核从字节解析实体、定义、注解目录及原始 flags，依 v13 限定静态模型独立逐层推导 True/False/Unknown，保留 Unknown 与 False 的三值组合；独立计算此子集 QueryID，核对来源身份、查询描述、validation、每层算子输入/输出/Unknown 计数、coverage、每个候选及从 Scan 到根的顺序叶见证。`work_units`、`engine_owned_bytes`、`engine_peak_owned_bytes` 仅检查类型、预算与相互边界，不独立推导精确值；复核结果显式列出这三项。未显式排序的候选行只复核成员集合与唯一性，不复核输出顺序。CLI 的重复 JSON 键和非有限数值均拒绝。依赖 `tests/integration/relational_test.py` 的实体目录、`entity_query_test.py` 的原始实体提取以及已有 `multisource.py`、`verify.py`；强制 Python 断言启用。它不是独立第三方 DEX 或 ART 验证器，不证明反射运行值、ClassLoader、APK、join/group、完整 v14 关系图或所有编码。

调用：

```powershell
python tools/evidence_verifier/reflection_scan_v14.py --root . --dex input.dex --query query.json --result output.json
```

测试入口 `tests/integration/reflection_scan_verifier_test.py` 和 `tests/integration/reflection_filter_verifier_test.py` 要求 `--root`、`--exe`、`--verifier` 和尚不存在的 `--out`；验证固定源码及样本哈希前后不变。未接受的能力或执行状态必须拒绝，不能依据该子集宣称通用 v14 见证验证已完成。

