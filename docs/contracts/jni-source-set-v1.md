# 显式 raw DEX 和 APK JNI 来源集合

`NativeEngine.openSources(bytes, slots, formats, allowNoDex)` 在同步调用中复制有序输入。仅接受1–8项，格式必须明确为 `SOURCE_RAW_DEX` 或 `SOURCE_APK`，输入字节总计不超过16 MiB，展开后的 DEX 总计不超过16 MiB、最多64个来源。调用方须在整个调用期间不修改任何数组、slot或字节。slot要求与 `openRawDexSet` 一致；只有 APK 可以显式设置 `allowNoDex`，否则没有规范 DEX 的 APK 会失败。并不自动发现 base/split、遍历应用路径或加载器。

`SourceSetInfo.inputCount()` / `input(i)` 保留输入顺序、格式、slot、内容身份、SHA-256、字节长度、容器元数据状态、展开数量及 allowNoDex。APK输入摘要对应整个压缩包；允许的资源包即使展开数量为零仍保留输入身份。`sourceCount()` / `source(i)` 按输入顺序和APK内数字 DEX 顺序提供展开后的 DEX 内容摘要与身份、inputIndex、slot、entryName与中央目录索引；raw DEX 的 entryName 为 null，索引为 -1。相同字节的不同 occurrence 保持不同身份。`MethodCandidate.sourceIndex` 是展开后的来源序号，`inputIndex` 是原始输入序号，不能假定两者相等；通过 sourceIndex 可取得 entryName。原 `openRawDexSet` 和其已有构造器、身份与结果语义保持兼容。

来源范围固定 incomplete：全部资源包或零匹配不能证明完整应用中不存在目标。每项的格式和 slot、所有数组长度和输入总字节数在复制前检查；任何来源解压、校验、预算或结构失败都不会发布部分快照，并返还注册表配额。输入字节是上限而非总 RSS 上限；解压和解析纳入核心约束，JNI/Java对象复制和系统内存不在统一账本。同步打开不可取消，必须显式关闭；复制后的输入/来源对象可在关闭后读取。

范围仅为静态来源及 method-v1 查询：未知APK版本、revision、ClassLoader顺序、反射绑定和运行时安装状态不会被推断。`containerMetadataChecked` 对 raw DEX 固定 false，对 APK 是内部容器检查标记，并不代表 APK 签名验证或可信来源；输入没有提供 expected SHA-256 绑定。CRC、DEX元数据、完整 DEX verifier、Android 装载和设备验收互不等价。
