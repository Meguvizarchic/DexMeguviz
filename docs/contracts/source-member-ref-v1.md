# 来源局部字段、方法和原型引用 v1

`dmg_snapshot_get_member_indices_v1` 在所选快照来源 occurrence 内读取 field_id 或 method_id，返回三个无符号本地索引：owner 的 type_id、名称的 string_id、字段的 type_id 或方法的 proto_id。必须持有快照引用；输出结构大小精确匹配，来源、kind、索引或大小无效返回 InvalidArgument，关闭快照返回 Closed。失败不修改输出。不暗示当前 DEX 中有定义，也不跨来源或 ClassLoader 解析。

`dmg_snapshot_copy_symbol_text_v1` 的 `DMG_SYMBOL_PROTO_V1` 将 proto_id 复制为完整 UTF-16 方法描述符，遵循既有长度上限、长度查询和失败原子性。组合既有 string_id/type_id 读取即可解析成员的静态名称与描述符。

Android Java/Kotlin 的 `fieldRefAt`、`methodRefAt` 返回独立 `long[3]`，顺序同上；`prototypeAt` 返回独立 String，支持单DEX和SourceSet。静态引用 ID 包括外部引用，不代表已定义、已加载、可调用或正确的运行时来源。方法同步执行；Java 数组和 String 不计入 native Engine 内存预算。
