# 实验性的追加基准日志与恢复

`CampaignJournal` 是可嵌入测试宿主的记录组件，接收调用方提供的 campaign ID、`real` 或 `synthetic_control` 标签、已固定的协议 SHA-256、调用方提供的身份 SHA-256 与 UTF-8 身份 JSON。它不发现设备、构造后端、执行查询、验证身份或判断结果正确性；标记 `real` 是调用方声明，不是工具认证。路径应由调用方选择为其私有目录中的**新文件**，不会覆盖已存在文件；如祖先包含符号链接将拒绝，调用方可事先在可信私有目录选择规范路径。`java.nio.file` 与 `java.util.Base64` 自 Android API 26 提供（[文件接口](https://developer.android.com/reference/java/nio/file/package-summary)、[Base64](https://developer.android.com/reference/java/util/Base64)）；项目当前 minSdk 为 27。此组件尚未在 Android/ART 上运行，文件系统实现行为仍需实测。

每次 `TaskProbe.measure` 结束后，调用 `append(result, facts)`，其通过 `ProbeRecordBridge` 把测量与显式事实写成一帧，包含原始采样及失败状态；采集失败或事实缺失的行也必须写入。每帧带连续序号、前帧摘要及 SHA-256 链，每次写入后调用 `FileChannel.force(true)`；这只请求操作系统同步，不保证硬件断电持久性，也不是签名或防恶意伪造认证。调用方应在所有需要的业务提交与同步释放完成后才结束测量；日志写入在计时包络外。调用期间不得并发修改 facts 或 result 数组。

`finish(gateEvidenceJsonUtf8)` 仅在调用方结束采集时写入 footer；传入 UTF-8 JSON 对象字节，外部门禁文件由调用方另行保存。`close()` 不补 footer，因此中途退出保持不完整。任一追加过程序列化、大小、写入或同步失败后该实例不允许再写 footer，已写字节保留；如果无法序列化原始 facts，日志最多保留错误类别，调用方必须另行留存原始对象。每次追加前检查文件长度/位置，但不能防范并发替换、同长度篡改或文件系统对路径的竞争，应用必须持有私有目录和单一写者。协调器接管时要求新建且只有头部的日志，并匹配协议摘要、身份摘要及身份 JSON 原始字节摘要；协调器持有期间公共追加、完成和关闭操作被拒绝。该检查不认证身份或解析协议内容，也不取代恢复器的规范 JSON 检查。日志可能包含宿主身份与路径，外发前需自行审阅。

```text
python -B tools/analyze_benchmark_journal.py --journal <journal.jsonl> --output <new-raw.json>
python -B tools/analyze_benchmark.py --protocol <frozen-protocol.json> --raw <new-raw.json>
```

恢复器只读原日志，严格检查帧序号、链、规范 Base64、JSON重复键和 identity 的规范摘要；只创建不存在的新输出，不修改或删除源日志。完整 footer 表示**日志格式完整**，不表示样本完整、身份真实或性能通过。中断、校验失败、身份不符或序列化错误会保留可信前缀，并向 `records` 明确加入 `complete=false` 的失败记录；不可验证尾部的长度和 SHA-256 会写入输出，原始日志必须一并保留。首帧无效时直接拒绝转换，不生成输出。恢复器退出码：0 为格式完整、2 为生成了不完整/无效的可恢复输出、1 为未能转换；若写输出中断，可能留下不完整新文件，不会自动重试或覆盖。输出中的外部门禁相对路径由现有分析器相对于输出文件所在目录验证；本工具不复制或认证门禁文件。

日志最多 99,998 条记录，单帧 payload 最多 32 MiB，日志总额由调用方设定且不超过 120 MiB；分析器输入也限制 128 MiB。当前只有 Java 8 编译（android.jar 位于 classpath）、自建假 PSS 的宿主连通以及格式/截断/篡改/分析器拒绝控制；真实磁盘写入/同步故障、断电持久性和 Android 文件系统行为尚未验证，**没有**真实 A/B/C 调度、真实设备、DexKit/BIL 运行或性能证据。
