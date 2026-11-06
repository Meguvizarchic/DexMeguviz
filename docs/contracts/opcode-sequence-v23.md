# 显式操作码序列方法查询 v23（候选）

直接 `method_defs` QueryIR 的 `where` 可指定 `opcodes`，需同时显式声明 `required_capabilities:["opcode_sequence"]`；输出 QueryID 的独立域为 `query:v23:`。不接受关系图、排序、top-n、反射/数值/类型使用等高级 profile 组合；可与同方法 metadata、字符串、字段及普通调用谓词和布尔组合，旧 profile 和 QueryID 不应改变。C ABI、CLI及独立Android同步桥使用同一profile；Android 的 `OpcodeQuery.startJob` 及快照 `startOpcodeJob` 提供非 scope v23 的异步 Job，使用现有有界批次、终态、取消和关闭合同；批次为暂定结果，EOF 不代表成功，须检查终态。旧 `startMethodJob` 仍拒绝 v23；`ScopedOpcodeQuery` 同步桥支持显式输入slot子范围，见 [范围合同](jni-scoped-opcode-v1.md)，不提供 scope Job。

例：`{"schema_version":1,"relation":"method_defs","where":{"opcodes":{"mode":"contains","values":[26,-1,96],"negative_wildcards":true,"count":{"min":3}}},"required_capabilities":["opcode_sequence"]}`。模式为 `contains`、`starts_with`、`ends_with`、`equals`。默认仅接受 0..255 的操作码；负 int32 默认返回 Unsupported，仅显式设置 `negative_wildcards:true` 才作为恰好一条任意操作码。可另显式启用 `signed16_coercion:true`，先将 int32 截取低16位并按有符号 int16 判断：非负值再取低8位，负值仍需独立通配开关；此选择进入 QueryID。该转换依据上游 Kotlin `toShort()` 与 FlatBuffers int16 源码推断，尚无实际二进制差分。DexKit 2.3.0源码的字节与空 optional 比较推断负数不能匹配任何字节，因此此 opt-in 语义有意不同，尚无真实DexKit/ART运行对照；序列最多4096项、每个查询与其他文本匹配器共享最多256组。默认大于255的正数返回 Unsupported；开启兼容转换时接受 int32，超过 int32 范围或非整数拒绝。`count` 是可选的闭区间或单个整数，统计整个方法操作码条数；宽指令计一条，数据payload计一条低字节0x00。无code定义按零条处理；空values不施加序列限制（含equals）。这些行为对照DexKit 2.3.0公开源码作了静态核对，但尚未进行真实DexKit运行时差分、全部边界或完整匹配API兼容验收；兼容转换和负值的显式通配分别是调用方选择，不是自动认证DexKit行为。

包含匹配在无通配符时为线性KMP；含通配符时用有界位并行状态，按状态字与解码/扫描计入逻辑work预算；数据、临时状态及查询计划由Engine内存账本约束。每方法一次checked静态解码，结果不表示控制流可达、运行时分派、来源/loader认证或ART完整验证。为避免将未序列化的指令数据误作缓存命中，显式持久facts provider对含此需求的调用回退直接解码，不读写该新事实缓存。暂不声明性能优势。

标准DEX 035/037/038/039/040可查询；041和未列的高级组合明确拒绝。C结果沿用现有执行/coverage/decision与方法来源语义；没有新opcode逐条见证，扫描范围及失败不能推断完整业务。Android/ART、完整Kotlin DSL、Job所有故障、跨使用方、批量和真实APK差分均需另行验证。

## 上游静态核对范围

对照固定 tag `2.3.0` 的上游资料：

- [DEX 操作码序列构建](https://github.com/LuckyPray/DexKit/blob/2.3.0/Core/dexkit/dex_item.cpp#L300-L350)：按指令宽度前进并记录低字节，含payload；无code方法保留空序列。
- [操作码条件](https://github.com/LuckyPray/DexKit/blob/2.3.0/Core/dexkit/dex_item_matcher.cpp#L1446-L1499)：范围、空集合与四模式分支。
- [序列搜索比较](https://github.com/LuckyPray/DexKit/blob/2.3.0/Core/dexkit/include/string_match.h#L27-L55)：搜索按字节与optional直接比较；尾部使用前述条件文件的标准equal。独立MSVC C++20比较见 `<LOCAL_PATH>
- [Kotlin序列化](https://github.com/LuckyPray/DexKit/blob/2.3.0/dexkit/src/main/java/org/luckypray/dexkit/query/matchers/base/OpCodesMatcher.kt#L316-L320)与[FlatBuffers字段](https://github.com/LuckyPray/DexKit/blob/2.3.0/Core/dexkit/include/schema/matchers_generated.h#L1106-L1107)：输入先转16位。

这些是源码与标准语义的静态推断，不是实际DexKit 2.3.0二进制、ART或真实APK差分；对于通配和截断需明确选择语义，禁止将候选样本描述为全量等价。
