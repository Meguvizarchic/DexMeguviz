# 绑定静态来源的注解文本匹配 v1（隔离候选）

`BoundAnnotationText.bind` 将一个已复制的 `AnnotationResult` 与一个存活的 `Snapshot` 或 `SourceSetSnapshot` 绑定。`text` 只能在这个结果中按索引选注解；库内部检查来源身份并调用原有来源局部 STRING/TYPE 读取，调用方不能传入解析器或另外指定来源索引。绑定时及每次调用均检查静态 snapshotId；单来源还检查来源索引、输入索引、SHA-256 和大小；来源集合还核对来源索引、输入索引、slot、摘要、contentId、occurrenceId、logicalDexId、大小、归档项位置和名称。无法通过这些检查时抛出 `IllegalArgumentException`，不输出不匹配结果。

静态身份是内容和元数据计算的值，不是唯一对象句柄：不同快照对象在来源一致时可能具有相同身份，也不能认证 APK 签名、运行时 ClassLoader、作用域、内存来源或注解运行时可见性。`AnnotationResult` 可离开采集快照而存活；该入口仅核对结果与当前快照的静态身份，不能证明结果原先由同一个 Java 快照对象产生。

匹配时把身份检查与解析放在快照对象监视器内，和显式 close 协调；不在锁内调用外部回调。关闭后继续匹配抛出关闭异常；`BoundAnnotationText` 的强引用不会阻止显式关闭，也不会关闭调用方快照。复制的 AnnotationResult 仍可离线使用。缺省元素仍为 UNKNOWN，其他三值与底层 AnnotationMatcher 相同；解析、格式、预算及关闭错误传播。

调用方需指定 UTF-16 单次文本长度上限（1 到 1048576）、单次元素上限和 EncodedValue 解码限制。它们不限制快照 info 的复制、进程总内存、跨次调用累积成本或时间。该同步接口应在非 UI 线程使用；不提供默认值、数组或嵌套注解语义，不构成完整 DexKit 替换或性能证明。
