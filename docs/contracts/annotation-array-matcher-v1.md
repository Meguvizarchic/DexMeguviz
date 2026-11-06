# 显式注解数组精确匹配 v1（隔离候选）

`AnnotationArrayMatcher.exact` 在已有 `AnnotationResult.Item` 中按注解 descriptor、可见性及元素名称查找显式编码值，并将一维 DEX ARRAY 与调用方给出的平行 `int[] kinds`、`long[] values` 精确比较。长度、顺序、元素 DEX 种类和对应值都须相同；支持空数组。整数为 DEX 有符号扩展后的值（CHAR 无符号）；FLOAT 用零扩展的 IEEE 754 32 位原始位（Java 可用 `Integer.toUnsignedLong(Float.floatToRawIntBits(x))`），DOUBLE 用 64 位原始位。BOOLEAN 用 0/1，NULL 用 0。方法、字段、枚举、STRING、TYPE 等引用使用无符号来源局部索引，不解析文本、验证表范围或认证该索引与结果属于同一来源。

显式元素不存在时为 UNKNOWN（可能有默认值）；已知不符为 NO_MATCH，完全相同为 MATCH。元素值不是数组时为 NO_MATCH；若数组任一子项是 ARRAY 或 ANNOTATION，先抛出 UnsupportedOperationException，即使长度或之前项目不符亦不报告 NO_MATCH。非法期望种类、无效输入、重复名称、解码错误与预算耗尽均抛出异常，无部分结果。非法或过深嵌套的解码错误可能早于不支持异常；它们同样不是 NO_MATCH。

调用方指定注解元素上限与 EncodedValue 字节、节点及深度限制；期望数组长度须不超过节点上限减一（根数组占一个节点），检查后才复制；实际元素先检查编码长度再复制与解码。数组参数不得在调用期间并发修改。预算分别限制此调用，不涵盖已有数据、Java 对象、整个进程内存、总工作量、跨调用累计或时间。

`AnnotationArrayMatcher.subsequence` 使用同样的输入和限制，判断期望项是否作为有序子序列出现在已显式编码的一维数组中：可跳过数组元素，但不能改变期望项顺序，每个实际元素最多匹配一个期望项，重复项需对应不同位置。空期望匹配任意已显式编码且无嵌套值的数组，包括空数组；元素缺失仍为 UNKNOWN。无论期望是否为空或已经找到，均先检查并拒绝所有嵌套数组和注解。此语义由本项目独立定义，未声明与 DexKit 的包含匹配相同。

不支持无序集合包含、嵌套数组或注解、默认值求解、文本解析及来源认证，不构成完整 DexKit matcher 或性能证明。

## 与固定上游源码的边界

[DexKit 2.3.0 注解数组匹配源码](https://github.com/LuckyPray/DexKit/blob/2.3.0/Core/dexkit/dex_item_matcher.cpp)中，编码数组的多个条件通过一对一匹配计算，包含和等值的数量要求不同；匹配不以调用方条件顺序为准。其浮点条件源码使用数值 `==`，本接口则比较原始位。因此这里的有序 `exact` / `subsequence` 均不能当作该上游匹配器等价实现；这是源码静态分析，仍需真实二进制差分。

## 无序标量一对一匹配

`unorderedScalars` 对已显式编码的一维数组执行无序一对一标量匹配，重复期望需要不同实际位置；`equalCount` 为 true 时还要求数组长度相等。支持数值、boolean、null，不支持局部引用或嵌套 matcher。FLOAT/DOUBLE 使用 IEEE 数值相等：正负零相等，NaN 不匹配任何数值。空条件在包含模式匹配任意无嵌套数组，相等长度模式只匹配空数组。缺失显式字段为 UNKNOWN；嵌套、错误输入与预算失败明确抛出。使用调用方节点上限限制期望数量，Java 哈希表自身的内存不计入引擎账本。

无序一对一及浮点相等规则是对固定上游源码的受限静态适配；该接口不能表达嵌套 matcher、引用语义或数量范围，缺省字段也与上游非匹配路径不同。未与上游二进制差分，不构成完整 DexKit 等价或性能证明。
