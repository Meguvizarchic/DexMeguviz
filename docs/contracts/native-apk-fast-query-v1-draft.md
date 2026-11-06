# NativeApkFastQuery 接入契约草案

此实验接口面向通用有序 APK 来源集，复用 FastDexQuery 预编译计划；调用方必须显式选择 `TRUSTED_IMMUTABLE_APK` 与 `CALLER_ASSERTS_VALID_SORTED_DEX`，保证 APK 在同步调用期间不可变、DEX 有效且索引符合约定。文件路径、长度和修改时间复核不证明不可变，接口不认证签名或运行时来源。支持每输入允许无 DEX 的资源包。

原生侧先准备来源清单，按输入顺序与 DEX 序号返回 occurrence（slot、输入与中央目录索引、序号、压缩和解压长度、CRC），各 worker 使用独立 ZIP reader，将存储或 DEFLATE 的 DEX 解压至原生缓冲，校验后直接传给 Fast 查询。可选只为有任一规则候选的来源计算 SHA-256；CRC 不是 SHA，也不是来源真实性证明。来源处理全部成功后才发布集合，规则级状态仍逐项保留；调用方必须检查 executionStatus、unknownRows、resultLimit 和 callerAssertedExhaustive，部分结果或失败不能解释为完整的不存在证明。

限额涵盖输入、来源、字节、各 reader 的 ZIP 元数据、并发解压缓冲、结果行及 wire；规则文本、调用边和其他局部限制由 Fast 计划执行限定。聚合行数在每个结果生成后核算，其他内存和瞬时峰值不全部受限，不能当作进程 RSS 上限。调用同步执行，不能取消；计划通过同步方法保持生命周期。

当前通过 Windows 主机 JNI 真实 APK 的方法与类查询、固定状态/关闭行为检查，以及 Android 双 ARM 交叉构建和静态封包检查。仍缺 Android 实际运行、API 27 文件访问、ZIP64 和广泛 APK、多个真实 APK/多规则差分、R8、真实 BIL 业务和同口径性能验证。不得将该接口或单次主机测量视为生产验收，也不改变既有严格路径。
