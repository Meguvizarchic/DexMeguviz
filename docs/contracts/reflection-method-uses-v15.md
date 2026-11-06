# 静态 reflection flags 与方法体引用谓词 v15

显式声明 `required_capabilities:["reflection_flags_static","reflection_method_uses"]`，并且直接 `method_defs` 查询中同时包含至少一个 `domain:"reflection"` 的标志谓词和至少一种 `using_strings`、`invokes`、`field_access` 谓词。新能力位 `8388608`，QueryID 为 `query:v15:`，编码域为 `DexMeguviz:QueryIR:reflection-method-uses-v15`；原 v13、v14 与不含本能力的原请求和 QueryID 不变。

允许既有布尔组合、scope、投影和 Enumerate、Exists、Unique；只允许无排序的直接方法查询。关系表达式、事件根、排序、TopN、继承、数值、接口解析、use-stream、composite、unique-one 等与此能力组合明确 Unsupported。能力缺失、空缺反射或方法体谓词及不符合上述条件均拒绝。此处 method uses 是单个方法体内谓词，不是 use-event 图或事件 Job。

静态反射模型及 Unknown 的前提见 `reflection-flags-v13.md`；事实由既有按需 checked 方法体提取，引用不代表运行时分派或 ClassLoader 绑定。`all` / `any` / `not` 保持既有三值逻辑，纯元数据优先，只有需要时读取方法体；Unknown 与确定结果按原布尔语义组合。失败、取消及预算沿用直接方法查询和 Job 契约，Job 批次为 provisional，必须读至 EOS 并检查最终状态。输出 access_flags 仍为 DEX 原始位。不能用候选数代替覆盖、决策或运行时业务验收。

首批证据限于固定自造 DEX 的独立字节与 CLI 比较，以及 Windows C ABI 同步/Job；并非完整 QueryIR、DEX verifier、全部错误路径、JNI、Android/ART 或 BIL 运行支持。已有 JNI 方法、实体及图入口按各自已公开 profile 继续拒绝 v15；单独的 JNI v15 入口范围见 `jni-reflection-method-uses-v15.md`。
