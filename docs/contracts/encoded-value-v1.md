# DEX encoded_value 有界 Java 解码

`EncodedValue.decode(element.encodedValue(), limits)` 将单个已复制的 DEX `encoded_value` 解码为不可变值树，不持有原生句柄；返回值可在原 Snapshot 关闭后使用。也可以解码调用者提供的独立字节。必须指定输入字节、节点及深度上限，分别不超过 8 MiB、100000 和 64；根节点深度为 1。复制的 Java 对象和调用者另外请求的原始字节副本没有纳入核心预算，不能据此承诺总 RSS 或墙钟时间。

支持 DEX 标准的 byte、short、char、int、long、float、double、method type、method handle、string、type、field、method、enum、array、annotation、null 和 boolean 标签。`kind` 和 `valueArg` 保留原始标签；`originalBytes()` 返回防御性副本。整数作对应有符号扩展（char 无符号）；浮点返回零扩展到其 IEEE 754 宽度的原始位，包括 NaN 载荷与负零。引用值返回无符号的来源局部索引，嵌套 annotation 返回类型索引和按编码顺序排列的名称索引及值；本接口不解析名称、类型、引用、可见性或运行时对象，也不凭这些索引认证来源或范围。

坏标签或参数、截断、ULEB128 超出 32 位、嵌套 annotation 的名称索引未严格递增、超过限额和尾随字节均抛出 `DecodeException`，不返回部分树；错误与限制当前使用同一个异常类型。错误的值种类访问器抛出 `IllegalStateException`。该独立解码器没有 DEX 表和版本上下文，不检查引用落入表内、annotation 类型是否为类、成员名语法或 038 之前能否使用 method-type/handle；原生读取和更完整的 DEX 检查分别负责其声明的范围。不得以本类判断完整 DEX 验证、DexKit matcher 兼容、设备、ART 或性能。

编码语义依据 [Android DEX 格式](https://source.android.com/docs/core/runtime/dex-format)；Java 示例：

```java
EncodedValue.Value v = EncodedValue.decode(element.encodedValue(),
    new EncodedValue.Limits(1024 * 1024, 10000, 64));
if (v.kind == EncodedValue.STRING) {
    long localStringIndex = v.referenceIndex();
}
```
