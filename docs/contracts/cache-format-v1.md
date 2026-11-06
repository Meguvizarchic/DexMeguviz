# 持久方法事实与完整搜索域依赖 v1

本批提供显式启用的内部 C++ 持久缓存和桌面工具，P4-01/P4-02 仍为 in_progress。默认不构建磁盘存储，不改变 C ABI/Android 的默认执行。启用 `DMG_WITH_PERSISTENT_FACTS=ON` 后生成 `dmg_persistent_facts` 和 `dexmeguviz_cache`；Android 显式启用该构建选项会报错。

## 实际消费路径

`cache::PersistentFacts` 实现 `MethodProvider`。调用方将 provider 传入内部 `reference::FactsCache` 的第四参数，再传给 `reference::execute`；`Evaluator::ensure_body` 会实际读取持久事实或调用原 `collect_method` 重建，而不是只运行独立编码工具。此模式关闭原有进程内 allocation-trace 缓存，避免把磁盘解码的分配顺序误当作原 decoder 的分配轨迹。未传 provider 的路径保持原状。

每片是一个方法在 **精确 demand mask** 下完整收集成功的事实。九类现有字段均有段：字符串、调用、字段、数值、数组元素、switch、branch、方法常量和类型使用。片键包含完整 DEX 字节 SHA-256、字节数、方法定义序号、精确 mask、parser/facts 版本及长度分帧域。物理事实不带来源 occurrence 或 APK 压缩信息，因此相同 DEX 可复用，但调用方仍在当前 snapshot 中解释本地 ID。metadata 仍由当前 reader 读取，未持久化完整定义/字符串目录。

命中事实由当前调用者 PMR 物化，方法引用/代码偏移/has-body/checked/mask 与当前 metadata 核对，代码长度与原 code_item 核对。每列检查记录数、字段宽度、枚举、所需 mask、PC 范围和顺序；带 opcode 的记录与原 DEX opcode 核对，并检查对应本地引用范围。无体/零 demand 的空事实有明确状态，不能冒充已检查指令。保存的 validation_work 仍由执行器计费；若超过当前剩余逻辑预算，重跑真实 collector，保持预算失败。使用点扫描和展开调用收集的显式 provider 接线已补齐，详见下方续接说明；默认仍无 provider。

## 磁盘格式与提交

文件为固定 little-endian，不落盘 STL、指针或 loader 对象。64 字节头依次包含：8 字节 `DMGFC001`；32 位 format/parser/facts/kind/section_count/complete；64 位 total_size/table_end/endian_marker/reserved。当前 format/parser/facts 都是 1；kind=1 为方法事实，kind=2 为方法符号定义集合。改变 parser 或事实语义必须同步提升版本，不能继续复用旧片。

段表每项 24 字节：32 位连续 section_id、32 位 required 标志、64 位相对文件起点 offset、64 位 length。方法片固定 11 段，解析集合固定 2 段；必须段数量、顺序、标志、连续边界与总长均精确匹配，未知版本/段、截断、越界或尾随数据拒绝。方法片第一段是完整键帧，第二段是方法状态，其余九段按列编码；每个记录字段显式按 64 位小端写入，读取时缩窄并检查，不依赖 C++ struct 布局。最后 64 字节为此前所有字节 SHA-256 的小写十六进制。摘要用于损坏检测，不是来源认证。

每次发布使用唯一 `.pending` 名称、独占创建、分块写入和 OS flush，关闭后以新的 `.shard` 硬链接目录项原子发布。读者只看 `.shard`；不替换、不删除任何旧片。成功和中断的 pending 都保留。硬链接不支持、权限、配额或写入错误只使缓存发布失败，当前真实收集结果仍可用；取消继续传播为取消。进程/系统中断可能丢失新目录项，后续当 miss 重建，不宣称目录元数据持久保证。

发布持有非阻塞 OS 文件锁（Windows LockFileEx / POSIX flock），锁的零字节文件保留，句柄关闭释放锁；竞争者跳过本次写入。默认每片 64 MiB、目录逻辑容量 256 MiB、目录项 2048、每列 1,048,576 条。目录容量按包括 pending 和 lock 的观察值计费，硬链接按两个名字保守计两份。对非本协议写者没有全局配额保证。扫描、读写和记录解码均有取消检查；SHA-256 单次计算及 OS 调用不保证实时抢占。

缓存目录必须由调用者显式选择、控制权限并信任其写者；拒绝已观察到的目录祖先/条目链接或 Windows reparse point，但不声称能防同权限恶意进程的并发替换。Windows 文件继承该目录 ACL，POSIX 新文件使用 0600。校验和与结构检查不认证恶意重写且重新计算摘要的内容。内部实例/统计由单线程使用，跨进程锁仅保护发布，不把任意调用方并发变成线程安全 API。

## 实际负依赖消费者

`resolve_method` 以完整 `(owner, name, prototype)` 搜索当前声明域，返回所有 `(source occurrence index, method definition ordinal)`，不只取首个。它实际读取或重建正/空定义集合，因此负依赖戳并非未消费的工具 hash。

键帧保存 namespace/model 字节、parser/facts 版本、来源完整性布尔、有序来源数量，以及每一来源的 slot、role、DEX 强摘要与字节数；最后分别保存三个 UTF-16 符号的单元长度及原始单元。所有可变值带明确长度，重复来源保留。新增、删除、重排、namespace/model、slot/role 或完整性改变都会产生不同依赖域，不能复用旧空集合或旧唯一性判断。已有单来源物理事实仍可命中。读回定义逐项核对当前来源、方法序号、完整符号及严格顺序；来源域不完整时始终返回 declared_complete=false，空集合不表示全局不存在。

`Scope.snapshot_id` 是可选的调用方声明，必须是 `snapshot:v2:` 后接64位小写十六进制。显式填写时解析域使用独立 v2 键，额外绑定该快照身份和既有完整有序 DEX 域；它应取自当前已打开 SourceSet 的 snapshot ID，覆盖原输入顺序、资源-only 输入与APK包装。输入新增、移除、换序或重包使快照身份变化时，解析集合不复用旧域。未填写继续使用旧 v1 域，**只能覆盖显式传入的 DEX 来源**，不能声称观测资源-only 输入或完整容器变化；旧分片与方法事实格式不变。绑定不验证字符串来源或确认 Scope 与 snapshot 一致，调用方须确保同一当前快照及稳定源；不认证签名、来源或 ClassLoader，结果仍只是静态定义集合。物理方法事实键不含snapshot，DEX不变时仍可跨资源重包命中。

这只是静态符号定义集合缓存；不是通用 QueryIR 结果缓存、业务最终接受状态、跨任意关系的否定依赖系统或运行时绑定缓存。符号搜索的 max_work 计方法访问数，命中也检查相同完整域方法数是否超限；其口径与查询 Work 不混用。

## 桌面真实 SourceSet 接线

`dexmeguviz_cache_sources CACHE_DIR QUERY.json SYMBOL.json SOURCES.json` 显式打开当前 raw/APK 输入快照；该模式由同一已打开Dataset取得 SourceSet namespace、scope、真实snapshot ID和逐DEX的slot/role/bytes/facts，再传给符号解析缓存及原有可选MethodProvider查询。无需手填snapshot ID；若SYMBOL.json提供snapshot_id会拒绝，提供namespace/complete时必须与SOURCES.json一致。旧raw入口和v1键不变。

SOURCES.json示例：

```json
{"schema_version":1,"namespace":"cli-v1","scope_complete":true,"inputs":[{"path":"base.apk","slot":"base","role":"base","format":"apk"},{"path":"code.apk","slot":"code","role":"code-split","format":"apk"},{"path":"resources.apk","slot":"resources","role":"resource-split","format":"apk"}]}
```

输入相对路径以SOURCES.json所在目录解释，slot/role/namespace要求非空ASCII；每项可选小写64位 `expected_sha256`。resource-split允许没有DEX但若含规范DEX仍按现有SourceSet规则展开和查询，不能把role视为无代码证明；普通base/code缺DEX会拒绝。输入1–8项、单文件64 MiB、总输入128 MiB，最多展开64 DEX/256 MiB；内核owned预算512 MiB，查询PMR另限256 MiB，磁盘配额另计，调用方输入缓冲/RSS不由这两个账本统一限制。首次打开先完整复制/解析来源，失败不运行查询或返回结果。工具单线程持有该snapshot至查询完成，不跨关闭、线程或进程共享内部Dataset。

`scope_complete`仍由调用方声明；输出`source_scope_authenticated=false`。真实snapshot ID绑定当前输入字节、出现顺序及相关DEX身份，但不认证APK签名、ClassLoader或实际安装集合；静态定义集合、查询结果和业务/运行时绑定仍分开。此内部桌面工具使用私有Dataset，不是新增公开C ABI、Android持久缓存接入、通用多线程服务或P4全部验收。

## 显式桌面 C ABI 扩展 v1

`include/dexmeguviz/persistent_cache_v1.h` 是独立、可选的桌面扩展；仅启用 `DMG_WITH_PERSISTENT_FACTS=ON` 并链接 `dmg_persistent_facts` 与 core 时提供实现。默认 core/Android 不启用它，旧C结构和旧query API不变。调用方明确选择可信私有目录和可信写者；open可能创建目录，不认证文件发布者。没有提供Job、异步、deadline或新增Android持久缓存入口。

使用者创建Engine后用 `dmg_persistent_cache_open_v1` 创建绑定该Engine的cache，传入长度明确的非空UTF-8目录、精确struct_size和ABI版本；内嵌NUL、非法UTF-8、超长或越界限额拒绝。零限额采用默认每片64 MiB、目录256 MiB、2048条目和每列1048576记录；可设置上限分别为256 MiB、4 GiB、65536条目和1048576记录。构建及路径访问失败不得产生可用句柄。以 `dmg_persistent_cache_execute_v1(cache,snapshot,query,...)` 显式执行同步已编译Query；三个对象必须同属Engine，调用者须在调用期间各自持有有效引用。该路径直接使用当前已打开Dataset的有序输入slot、DEX出现、scope和事实，保留原结果物化和完整/部分范围语义；仅方法事实可跨运行复用，查询决定/唯一性、负缓存与运行时绑定不作为该API输出的持久事实。

同一cache句柄的execute和stats用互斥锁串行。close原子关闭新操作准入，不等待、不取消已通过准入的同步执行；之后等待的execute返回CLOSED，stats仍可读取且可能等待当前执行。Snapshot close和Engine shutdown沿既有同步查询合同；两者关闭后的新调用拒绝，先通过准入的执行可继续。与所有现有C句柄相同，使用/retain/release不得在没有各自有效引用时并发；最后release前须完成本线程对句柄的使用，伪造/释放后指针不在合同内。Result仍保活Engine、Dataset及Query，cache和Snapshot释放后只要Result持有引用即可读取。

实际facts、查询scratch、Result和cache句柄经Engine的相应PMR账本分配；缓存目录路径、枚举向量、操作系统锁和文件系统IO缓冲等仍有受本扩展选项约束的独立开销，不在Engine managed-bytes或RSS承诺内。缓存命中保留逻辑work口径，但不保证与原collector在极紧预算、分配故障或磁盘错误下的分配/失败顺序完全一致。缓存损坏按现有合同回退原collector；不安全目录或不可创建目录使open失败，C++异常不跨C边界。静态源身份不认证APK签名、ClassLoader、安装范围或producer；cache并不使业务结果自动可信。

## 桌面入口与当前验证

`dexmeguviz_cache CACHE_DIR QUERY.json SYMBOL.json DEX [DEX...]` 读取有序 raw DEX，执行符号解析及带 provider 的真实 QueryIR 查询，输出解析命中、query_cache_hits/rebuilds、候选身份和逻辑 work。SYMBOL.json 包含 owner/name/prototype，可选 namespace/model/complete/snapshot_id；输出的 snapshot_domain_bound 只说明提供了格式有效的声明，非身份认证。工具 namespace/model 限 ASCII，内部 API 接受任意字节。输入、PMR 和磁盘分别有明确上限，未宣称进程 RSS 总账。

Windows Release 构建和四个功能连通场景通过：冷查询重建、热查询实际命中并保持候选/逻辑 work、增加含目标的来源使旧负依赖失效、损坏一个方法片后拒绝并重新收集。最后一轮包含 OS 发布锁。最初工具把 Progress 当带资源构造器导致编译错误，已修复，原日志保留。没有执行完整 F12、全部九类事实的独立差分、来源移除/重排专项、全量 fault/并发/取消/压力/ASan 或 POSIX 验证。

读取/序列化开销受独立缓存限额约束，不等同 query max_work 或进程 RSS；磁盘命中不重放原 decoder 分配轨迹，也不声明故障发生点/错误顺序严格等价。文件损坏或读缓存分配失败会尝试真实 collector，不能返回成功空 facts；真实资源不足、损坏输入、取消和预算错误仍失败。上述资源/失败时序、完整 L1 目录和一般关系负依赖仍需继续实现与统一专项验收。

## 使用点、展开和反向构建续接

`collect_uses` 在内部参数末尾增加可选 MethodProvider，默认 nullptr 原样调用现有 collector。四类使用点（string/invoke/field/type）在逐方法完成后用当前 source_index 重新构造 UseRecord，磁盘事实不持有旧 occurrence。原来的 source/caller/PC、逐方法回调、type-use discard-after-callback、剩余共享工作和结果上限处理均保留。缓存只替换取得 MethodFacts 的步骤，不跳过事件发布、查询 residual 或扫描进度计费。

BoundedExpand 的 outgoing 调用收集、incoming 全域边表构建，以及 walk/emit 中的方法体谓词均使用同一显式 provider。incoming 热查询可以复用磁盘方法事实，但仍为本次声明域重新组装边表；不把该行为报告为磁盘逆索引命中。路径、来源分支、frontier 和搜索范围不存入物理方法片。

ReverseRegistry 内部 lookup/page 的可选 provider 只进入尚未发布的索引构建。完整索引复用仍使用已拥有的 rows，按原 construction_work 计费并检查当前限额，不再次读盘。GraphExecutor 的显式 reverse-target-join 将本次 provider 传给 registry。registry 仍绑定调用方维持的不可变来源会话，不用于跨已更换 Dataset 的 source_index 复用；本批没有持久化逆索引或改变旧公共 C ABI。

所有 provider 消费点通过统一内部 guard，核对方法引用、代码偏移、精确 demand、has-body/checked 状态、九类向量使用本请求 PMR、保存的 validation_work 不超过剩余预算，并在返回后检查取消。provider 合同错误直接失败，不能变成空关系；持久实现自身在损坏/不兼容/读失败时仍回退真实 collector。默认 nullptr 路径保持原 collector 的调用方式。分片 IO/哈希开销与 allocation-fault 时序限制仍适用，未据命中计数声明实际性能提升。

为给实验 DEX041 逻辑头身份留出明确门槛，本版只对 035/037/038/039/040 读写持久片。其他版本的 MethodFacts 直接重新收集，含其来源的 resolve_method 也重新解析且不返回可复用 dependency_digest。待 Facts.header_offset/逻辑范围合同落地后再升级物理键与有序依赖域；不得用同一完整容器摘要加 ordinal 冒充不同逻辑头身份。

本批 Windows Release 构建通过，并运行 invoke/type 两类扫描及 outgoing/incoming 展开四对冷/热真实查询；热路径实际命中，候选、逻辑 work、unknown 和 result_limit 与冷路径相同。没有执行所有使用点族专项、reverse-registry 复用压力、预算/取消故障矩阵、ABI/ASan/设备或041验证。P4仍进行中，统一专项继续后置。

Android的显式method-v1同步可选桥独立构建，入口、生命周期及验证边界见 [android-persistent-facts-v1](android-persistent-facts-v1.md)。此可选构建不改变默认Android、桌面C ABI或其他profile。
