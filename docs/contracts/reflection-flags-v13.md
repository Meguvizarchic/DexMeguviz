# 静态 reflection flags v13

此 profile 只定义一种基于 DEX 声明的、版本化静态投影；它不是 Java 反射对象、ClassLoader 选择或任何设备 ART 实际返回值的证明。完整 Q05 和 P1-08 验收尚未完成。

调用方在 JSON 中显式使用 `required_capabilities:["reflection_flags_static"]`，并在 `flags` 或 `owner_flags` 中指定 `domain:"reflection"`；这两者必须同时出现。v13 只支持直接实体元数据查询与现有布尔组合、作用域；关系对象、排序、TopN、方法体谓词，以及 use、继承、数值、接口解析、use-stream、composite 或 unique-one 等能力组合均拒绝。v15 另以显式能力支持限定的直接方法体谓词，见 `reflection-method-uses-v15.md`。能力位为 2097152，v13 独立 QueryID 使用 `query:v13:` 及 ASCII 域 `DexMeguviz:QueryIR:reflection-flags-v13`；同查询中的 raw DEX 标志仍用 `domain:"dex"`。旧请求未显式选择能力时 reflection 仍 Unsupported，既有 raw 请求的规范编码与 QueryID 不变。

模型按所查固定 AOSP 源码中的变换应用到已读取的 **静态 DEX 位**，其准确性以运行时实际位值与这些静态位一致为条件：

- Method/Constructor：先在 abstract 时清掉 native，再清除低位 `0x20`，若 DEX 声明 `0x20000` 则设置 `0x20`，最后仅保留低 16 位。执行锁语义与该转换不同；例如 `0x121 → 0x101`、`0x20121 → 0x121`。原始 DEX 字段/输出的 access_flags 仍保留 raw 值。
- Field：保留低 16 位。仅有当前来源内本地字段定义时才能求值，外部引用缺定义为 Unknown。
- Class / `owner_flags`：当前只保存注解目录偏移，没有提取 InnerClass.accessFlags。注解目录非零一律 Unknown（即使实际只有无关注解）；为零时在限定静态前提下取类声明低 16 位。外部类型、无本地 owner 等为 Unknown。数组/原始类型或代理类的运行时修饰符不在静态模型内。
- 互相冲突的 visibility 位、字段非标准低位、非 native 方法的低位 synchronized、方法不属于所列声明位或 class 不属于顶层 DEX 位的编码返回 Unknown；未识别高位亦返回 Unknown。这样不会把可能存在的 hiddenapi 编码无条件当成公开修饰符；不能保证穷尽所有厂商格式。

Unknown 不等于零；所有模式、零掩码和 NOT 保持现有三值行为。存在 Unknown 属性时，除明确短路为 False/True 外，覆盖与决策按现有规则保守报告。查询行仍返回 raw flags：投影值不作为新的 C ABI 结果字段或独立运行时证明；若需要复核，应重新按本契约从源字节推导并验证前提。

独立来源（逐文件固定修订，尚未证明构成同一 Android 发行版）：

- [libcore Executable.fixMethodFlags](https://android.googlesource.com/platform/libcore/+/e1f193f/ojluni/src/main/java/java/lang/reflect/Executable.java)
- [libcore Field.getModifiers](https://android.googlesource.com/platform/libcore/+/2e317a02b5a8f9b319488ab9311521e8b4f87a0a/libart/src/main/java/java/lang/reflect/Field.java)
- [libcore Class.getModifiers](https://android.googlesource.com/platform/libcore/+/f080dbcfd1b59b3e1a49b1f1aad90051a9787cdc/ojluni/src/main/java/java/lang/Class.java) 与 [ART InnerClass 回退路径](https://android.googlesource.com/platform/art/+/5a2301d897294ff4ee6de71f459dc2566dc3fa1a/runtime/mirror/class.cc)
- [DEX access flags 和 InnerClass 注解格式](https://source.android.com/docs/core/runtime/dex-format)；[ART hiddenapi 位编码](https://android.googlesource.com/platform/art/+/refs/heads/main/tools/hiddenapi/README.md)

原测试继续要求未选择此能力时拒绝 reflection。固定 DEX 的静态映射、CLI 对照及 C ABI/Job 测试与证据记录在项目状态中；故障预算、目标设备反射及上游版本匹配仍需验证。
