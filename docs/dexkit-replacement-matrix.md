# DexKit 2.3.0 替换能力与证据边界

用户要求全量替换DexKit依赖，并使SDK具备跨宿主复用性、兼容性和性能优势。当前未达成该目标。此表基于本机已有 DexKit 2.3.0 AAR 的公开字节码签名，以及 DexMeguviz 当前源码/契约；列举能力族而非声称已逐个重放164个顶层类的所有方法。完整签名清单与AAR摘要在 `<LOCAL_PATH>

| DexKit能力族 | DexMeguviz当前状态 | 未闭合部分 |
|---|---|---|
| 文件/字节/多个DEX与APK来源 | C/CLI和Android显式SourceSet、raw/APK/FD，来源顺序/预算与静态身份；Android有caller声明的slot子范围 | 不自动证明应用完整或loader来源；DexKit按ClassLoader自动发现的等价路径尚未完成 |
| `findClass`/`findMethod`/`findField` 与基础名称、签名、flags | 直接实体、方法、关系QueryIR与Kotlin类型化子集 | 全部DexKit matcher组合、边界及结果顺序未逐项证等价；非同包名的源码/二进制drop-in |
| 字符串、字段、数值、调用、类型、opcode | QueryIR使用点、单方法facts及受限v23 opcode序列查询C/Android入口；保留局部索引、PC与原始数值位宽 | 尚未覆盖所有DexKit matcher/组合或完成完整数据值的独立对照；静态调用不等于运行时分派 |
| 参数类型与debug参数名 | 通用C及Android Java/Kotlin/JNI接口，缺定义/体/debug/NO_INDEX分开；固定主机样本通过 | 不能保证编译器保留名字，最终Android及反射行为未验 |
| 类、字段、方法、参数注解 | 通用C及Android Java/Kotlin/JNI保留注解类型、元素名和原始encoded_value；Java提供有字节/节点/深度上限的结构化解码，可读取数组和嵌套注解的来源局部索引 | 字符串、类型、字段、方法和原型索引可按来源组合解析；method-handle引用及完整annotation matcher/默认值语义未完成，解码不构成完整DEX验证 |
| 调用者/被调用者、类继承、接口与字段关系 | 受限图、独立见证与有界展开；部分Java/Kotlin入口 | 不支持所有图组合、动态分派、完整ClassLoader解析或全部DexKit关系语义 |
| `getClassData`/`getMethodData`/`getFieldData`及结果对象 | 实体/来源/符号、方法facts和绑定器提供部分信息 | 尚非DexKit完整对象模型或所有结果getter，原类型与构造协议不兼容 |
| `initFullCache`、线程与并发配置 | 可选持久方法事实、Engine预算及Job/Batch | 不是DexKit完整预热/并发API；cache命中率、内存和速度均未对照 |
| `exportDexFile` | C及Android可按快照来源读取或复制完整静态DEX字节 | 尚无DexKit路径批量导出同签名实现；final3同源AAR和固定宿主样本已验证，最新接口未在设备运行，不认证loader |

依赖退出分层：当前 DexMeguviz 的源码生产目录检索未发现 `org.luckypray` 导入；当前同源AAR的类与两个ARM native库及运行时依赖报告的ASCII/UTF-16标记扫描未见DexKit，运行时报告为空；这不能证明改名代码、外部加载或消费者传递闭包不存在。当前BIL仍有 `implementation(libs.dexkit)`、`DexKitAssistEngine` 与 `System.loadLibrary("dexkit")`；历史debug APK含 `libdexkit.so`。因此BIL尚未退出DexKit。最终应在交付源码、全部构建配置/依赖图、运行时类与native产物上复核零残留；独立对照和历史资料只留作证据，不进入交付依赖图。

性能与兼容优于DexKit必须在同设备、同APK、相同完整查询语义、候选/角色/结果、生命周期及资源包络下实测；延迟、冷暖、内存、ABI/页大小、失败与恢复应分别有数据。当前没有正式A/B/C结果，不能宣称更快、更省或兼容性更好。
