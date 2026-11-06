# 类注解显式字符串等值查询 v25（隔离候选）

在 v24 直接 class_defs 约束内，`where.annotation.element` 可选择 `{"name":"str","string":"雪"}`；必须同时声明 `class_annotation_static` 与 `class_annotation_string_static`，QueryID 为 `query:v25:`。每个 element 恰好指定 int 或 string 之一；v25 可以在布尔组合中与已有 v24 类型/数值叶组合，仍拒绝关系图、排序、top-n 和其他高级 profile 混用。只有 int 的原 v24 查询、QueryID 及工作计量不变；未请求新能力、无字符串谓词、错误组合均拒绝。

比较对象是当前 DEX 中显式 `VALUE_STRING` 解出的本来源 string_id 所指 UTF-16 单元；查询值也是精确 UTF-16 单元，包含空串、NUL 与允许 JSON Unicode escape 表示的孤立代理项。普通 UTF-8 输入按既有 JSON scalar 规则转换；不进行 Unicode 规范化、大小写折叠或跨来源索引比较。注解不匹配、visibility 不符、已编码元素种类/内容不同为 No；匹配注解未显式编码该元素为 Unknown，not Unknown 仍为 Unknown；不解析默认值。

逐单元文本比较使用既有 Work 预算和协作取消，格式/索引损坏、预算和取消不转为空匹配；缓存继续局限同一来源的 evaluator。QueryID 的 v25 域和新叶编码包含类型标志、元素名称、字符串值的 UTF-16 单元，不包含本地索引；等价 JSON escape 具有相同 ID，不同值具有不同 ID。

旧 32-bit 能力位图不变。v25 旧 info/explain getter 继续返回 Unsupported；v2 额外能力字符串为 `class_annotation_static;class_annotation_string_static`。旧 Android v24 桥按 v24 ID 和精确能力过滤，拒绝 v25；独立 `ClassAnnotationStringQuery` 提供全输入同步及非 scope Job，`ScopedClassAnnotationStringQuery` 提供显式范围同步，范围 Job 可通过 `ScopedClassAnnotationStringQuery.start` 使用。独立 host 样本覆盖两个不同 DEX 的同 string_id 异值、UTF-16 边界、空值、Unknown、预算和取消；尚无 Android/ART、真实 APK、全部语义或 DexKit 性能/等价证明。
