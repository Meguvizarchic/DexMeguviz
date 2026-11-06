# 受控 APK 文件范围 SourceSet v1（实验候选）

`dmg_snapshot_open_apk_fds_v1` 同步接收 1–8 个有序 APK 文件范围，目标 Snapshot 完整性由调用方显式声明，不能据此推断 Android ClassLoader 或运行时来源完整；Android 接入必须使用 incomplete。每项提供有效只读 fd、offset、length、非空唯一 slot、可选 role/expected SHA-256 与 allow_no_dex。调用方在返回前保持 fd、结构和字符串有效，文件内容亦需保持稳定。fd 的当前位置不改变、所有权不转移；Windows 使用独立重开并使用 overlapped 指定偏移读取，若无法安全重开则失败；POSIX 复制 fd 并使用 pread，非普通文件拒绝。长度、偏移溢出及文件实际范围均有检查。

新APK入口的POSIX副本仅使用原子的 `F_DUPFD_CLOEXEC` 创建；构建平台缺少该能力或运行环境不支持时返回 Unsupported，不以非原子的 dup+F_SETFD 回退。fd资源耗尽返回 BudgetExceeded，内核内存耗尽返回 OutOfMemory，无效 fd 返回 InvalidArgument。该标志仅使副本在成功 exec 时关闭，不能阻止 fork 后、exec 前或纯 fork 子进程暂时继承。caller 持有的原 fd、Android Java 层自行打开或复制的 fd 不由该标志保护；旧 raw fd 行为不变。

每个归档一次性复制到 Engine 受管 source 内存，计算范围 SHA-256 并与可选预期摘要比较；成功后复用核心既有 ZIP 预检、CRC/头一致性和 root classes.dex/classesN.dex 规则，按数字顺序提取和保留 DEX。处理下一个输入之前释放当前压缩缓冲，但本批已展开 DEX、Facts、ZIP 中间结果和控制结构可能同时驻留。输入身份为完整指定范围的 APK 字节摘要，slot/role、数字 DEX 及中央目录 index 按已有 SourceSet 身份编码；同内容不同 slot 是不同 occurrence。allow_no_dex 为真时保留零 DEX 输入，仅表示该输入中无受支持的 DEX，不证明整个应用或 loader 无代码。

入口先检查结构、fd数字、slot 和输入额度，再建立 Dataset；每项复制前在最终用于读取的独立句柄上检查实际 fd、普通文件/长度与范围，然后才分配该归档的大块缓冲。Dataset 等早期小分配或前面的输入仍可能先失败，多个错误的顺序不作全局保证。旧 raw `dmg_snapshot_open_fd` 的分配/验证顺序保持原行为。

必须显式提供每包/累计压缩字节、每 DEX/累计解压字节、最大归档条目、中央目录字节、累计名称字节和最多64个来源；Engine 自身 `max_source_bytes` 与 owned/account 预算仍生效。新增选项不得超过已支持的 ZIP 条目/目录/名称上限；超过任一预算返回 BudgetExceeded，不自动扩大旧限制。预算涵盖核心受管分配，OS allocator 元数据、fd、栈及RSS不在该账本；大APK可能耗尽32位地址空间或系统内存，不承诺移动端性能。ZIP 处理结果在校验完所有输入后才发布；任何错误都将 *out 置NULL并释放临时归档和部分 Dataset，调用方应检查错误状态，不能把失败当空集合。

复制获得的字节与 SHA 只是本次复制的内容身份；未提供可信 expected SHA 时不证明来源修订。`dup` 或重开不冻结底层文件，检查文件大小、摘要或前后元数据都不能排除读期间更改及恢复（ABA）。本接口不使用 mmap，不声称修改/截断可被捕获为 C++异常。此版不提供取消/deadline，read/哈希/解压/元数据解析可能持续至返回；不得在UI线程调用或声称硬实时。

本接口不改变旧 `dmg_snapshot_open_sources`、`dmg_snapshot_open_fd` 或 JNI byte[] 的范围/上限，尚未接入 Android ApplicationInfo/PFD 适配器。固定 host 验证、构建及交叉链接不代表真实设备、ART、安装包签名或运行时绑定验证。
