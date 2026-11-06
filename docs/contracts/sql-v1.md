# 桌面 SQLite 方法表内部原型

当前功能补充见 [目录与二进制值扩展](sql-catalog-bytes-v2.md)：新增 logical_dex/type_uses/string_data 三个表及内部 BLOB 通道。下文早期历史限制中“原始 MUTF-8 未实现”和“仅 NULL/INTEGER/TEXT”由该补充替代；既有表列保持不变。

状态：默认关闭的实验性桌面适配器。P3-01 的 P2-01 和 P2-07 前置仍未满足；这不是冻结后的完整 catalog、稳定 C ABI、JNI、AAR 或发布能力。独立桌面 CLI 也是实验性入口。只有桌面显式启用 `DMG_WITH_SQLITE` 才构建，Android 启用该选项会被拒绝。SQLite 为既有授权的 3.54.1，使用工程的固定源码和许可记录。

## 表、来源和 NULL

内部 `SqlSession::open` 自行使用所链接的 SQLite 创建私有内存连接，接收有效且保持存活的 `dmg_snapshot`，不接受或暴露 `sqlite3*` / `sqlite3_stmt*`。会话注册只读的 `dmg_snapshot`、`dmg_inputs`、`dmg_sources` 和 `dmg_method_refs`、`dmg_method_defs`、`dmg_field_refs`、`dmg_field_defs`、`dmg_type_refs`、`dmg_class_defs`、`dmg_string_values`、`dmg_string_uses`、`dmg_invoke_sites` 和 `dmg_field_uses`，从快照取得不可变 Engine Dataset，并一直持有 Dataset，进而保活来源、借用 lease 和 Engine 内存资源。调用时不得并发释放快照句柄；会话所有方法和析构目前只支持单线程。

一行分别对应某个已选择来源中的一个 method_id 或一个本地方法定义；`source_index` 是当前 Engine 快照中展开的来源 occurrence 序号，不是持久身份或内容摘要。相同字节作为两个 occurrence 时产生两组行。

| 列 | 语义 |
| --- | --- |
| source_index, ordinal | 当前数据集中的来源序号及该表内本地序号 |
| reference_index | 本地 method_id 序号，引用不隐含运行时定义 |
| definition_ordinal | 已知本地定义序号；无定义为 NULL |
| owner, name, prototype | SQLite TEXT，按 SQLite 文本和 collation 规则处理；不承诺 DEX 专用比较 |
| access_flags, declaration_offset | 已知本地定义的 raw DEX flags 和声明偏移；无定义为 NULL |
| code_offset | method_defs 中有 code_item 时为偏移，缺代码为 NULL；method_refs 始终为 NULL，因为引用行不提供代码属性 |

`rowid` 是 `(source_index << 32) | ordinal`，只在同一表和当前快照内区分行，不是跨快照的稳定身份。来源数最多1024，序号由 Engine 按展开顺序给出。完整的资源包来源可以没有 DEX，此时方法表为空；旧 `open` 在快照标记为不完整时仍拒绝注册，显式 `open_scoped` 可接纳并要求使用带范围标签的结果接口。SQL 入口不能另行传入或覆盖完整性标志：多来源 SourceSet 的 `scope_complete` 来自调用方的范围声明，而 legacy 单来源入口默认设为 true、没有显式声明参数。两者都不能独立证明实际运行环境中不存在其他来源；COUNT / NOT EXISTS 只针对该快照范围。

字段表一行对应某个来源 occurrence 中的 `field_id` 或本地字段定义。两表列为 `source_index, ordinal, reference_index, definition_ordinal, owner, name, type_descriptor, access_flags, declaration_offset`；引用缺少本地定义时，定义序号、flags 和声明偏移均为 NULL。引用表中的已知定义只表示该 DEX 的静态声明，不表示跨来源或运行时解析。重复来源保持重复行，rowid 规则与方法表相同，仅在当前表和快照内有效。

类型引用表一行对应一个来源 occurrence 中的 type_id，包括基础类型、数组类型和当前 DEX 未定义的引用类型；类定义表一行对应同一 DEX 的一个 class_def。两表列为 `source_index, ordinal, reference_index, definition_ordinal, descriptor, access_flags, definition_offset, superclass_descriptor`。未在同一 DEX 定义的类型引用，其定义序号、标志、定义偏移和父类均为 NULL；已定义根类没有父类时 `superclass_descriptor` 亦为 NULL，因此应结合 `definition_ordinal` 判断是哪一种情况。父类是静态引用描述符，不解析其他来源、类加载器或运行时继承。类型引用表不因其他 DEX 存在定义而补全本地属性；重复来源保留重复行，rowid 只在当前表和快照内有效。

三个使用点表每行对应一个静态指令事实，列为 `source_index, caller_ordinal, caller_reference_index, code_offset, dex_pc, opcode, target_domain, target_index, extra_proto`。身份由来源、类型、调用者定义序号和 DEX code-unit PC 组成；相同目标在不同 PC 或来源出现时保留多行。`target_domain` 数值 0/1/2/3/4 分别表示字符串、字段引用、方法引用、方法和原型、call-site；仅 polymorphic 调用提供 `extra_proto`，其他为 NULL。它们是本地引用，不推断运行时目标或 bootstrap。表内 rowid 是当前完整扫描按来源、方法及 PC 顺序的从 1 开始的序号，不是跨快照稳定身份。

`dmg_string_values` 每行对应某个来源 occurrence 的一个本地 string_id，列为 `source_index, ordinal, value`；`value` 经严格 UTF-16 标量转换后以显式长度输入 SQLite UTF-8 文本，空串是非 NULL 文本，内嵌 NUL 和开头 U+FEFF/U+FFFE 均保留。`rowid` 为 `(source_index << 32) | ordinal`，相同字节的多个来源仍各有一行；这不是跨快照身份。比较、排序与 LIKE 使用 SQLite 语义，未提供原始 MUTF-8 BLOB 或 DEX 专用比较。

## 执行与限制

内部单线程 `SqlSession` 可显式 `enable_profiling(true)`，默认关闭；每次进入内部语句执行器后，`last_query_profile` 返回一个按会话递增的最近观测：SQLite 状态、prepare 是否尝试/成功、首次 step 是否发生及其状态、暂存和成功提交的行数、进度回调数，以及单调时钟测得的 prepare、首次 step 和执行器总耗时（微秒）。这些时间是调用线程的经过时间，不是 CPU、总内存、Engine 或跨会话性能度量；多次调用可供调用方标记首次和后续调用，但本接口不声明索引、事实缓存或执行计划复用。计数在溢出时饱和。不开启时不记录；开关状态变化会清除最近观测，序号不重置，查询不到记录时返回 `SQLITE_NOTFOUND` 且不改输出，关闭的会话返回 `SQLITE_MISUSE`。

统计只覆盖内部语句执行器：参数校验或预取消也可生成记录，但进入执行器之前的范围标签分配失败、接口模式拒绝，以及执行器成功后游标自身的分配/取消失败不在该状态内。`rows_staged` 是失败前私有暂存数量，不表示已交付；仅成功时 `rows_committed` 非零或按实际空结果为零。统计不保存 SQL 内容、参数或结果。会话与其统计读取沿用既有单线程、不重入约束，不能作为 provisional/final 协议或完整 P3-04 验收。

内部 `SqlSiteLimits` 可分别设置非零 `max_statement_work` 和 `max_statement_records`，对单条语句访问三个使用点表时所有 `xFilter` 及所有来源的扫描工作、产生的静态事件数累计限额；零表示不启用该项，默认维持原来的逐次扫描限制。非零工作上限最多 100,000,000，事件上限最多 100,000；不合法值在打开会话时拒绝。每条 `query`/`query_scoped` 独立开始并在所有退出路径结束时清除计数；超额返回 `SQLITE_TOOBIG`，结果不提交。用点收集器可能在当前来源扫描完成后才检查累计事件数，临时缓冲仍受原有逐次扫描和 Engine scratch 资源限制。没有访问使用点表的语句不消耗这些额度。工作计数沿用现有收集器定义；它不是 SQLite 指令、prepare、SQLite 内存、Engine 总账、时间或 RSS 上限。首次扫描用尽工作额度后，后续涉及来源的扫描即使可能没有事件也会保守失败。

默认会话的 `xBestIndex` 不消费任何条件，`xFilter` 从完整范围开始。实验性 `open_planned` / `open_scoped_planned` 显式启用 `metadata_identity_equality` 后，七种元数据表可选择可用的 `rowid`、`source_index`、`ordinal` 等值约束作为参数；优先选择第一个可用的非整批 IN 的 rowid 等值约束，其他约束保留给 SQLite 检查。`xFilter` 仅对实际 SQLite INTEGER 值缩小范围，其他类型回退完整扫描；负数 rowid 或越界的来源及序号不匹配。此行为仅限七种元数据表，默认关闭。`sqlite3_vtab_in(...,-1)` 可识别能一次处理全部值的 IN；未单独启用下述 IN 选项时拒绝选择这些约束。不可一次处理的 IN 也可能被 SQLite 当作等值约束逐值调用 `xFilter`。原值仍交由 SQLite 检查残余条件，包括重复约束、亲和性和 collation；不等式、使用点与来源目录表不下推。各模式均不设置 `omit`、`orderByConsumed` 或唯一索引标志，不下推 LIMIT/OFFSET。优化可能改变访问行及求值顺序，从而改变未命中行的文本转换错误和资源或取消阈值是否触发；不承诺与默认模式的逐步执行或错误时点等价。SQLite 负责 WHERE、JOIN、排序和截断。只读模块不实现更新。跨来源查询不会自动绑定 ClassLoader、合并同名定义或推断运行时解析。

另可显式设置 `metadata_identity_in`（必须同时启用 `metadata_identity_equality`），使用 SQLite 的 `sqlite3_vtab_in_first` / `sqlite3_vtab_in_next` 接收可整批处理的 `source_index` 和 `ordinal` IN。整数键去重并按原表顺序扫描，保留来源 occurrence 和连接产生的重复行；NULL 及越界整数不产生匹配。存在浮点、文本或其他非整数值时该列回退完整扫描，由 SQLite 的残余条件判断亲和性；每列最多读取 4096 个 IN 元素，超出则回退完整扫描。非整批 IN 仍可能由 SQLite 逐值调用。调用期间暂存键使用 Engine scratch 账本；SQLite 构建 RHS、执行查询及所有进程内存不受这个键数上限约束。枚举时在首项及每 64 项检查取消；分配、取消或 SQLite IN 枚举失败返回错误并保留调用方旧结果；不声称错误时序与默认扫描一致。

每个使用点表的 xFilter 在返回任何行前完整扫描该快照所有来源和方法；损坏、未支持、预算或分配失败分别返回 SQLite 错误，不能变成正常空表。使用点暂存及解码使用 Engine scratch 账本，但 SQLite 自身不在账本内。每次扫描的默认总工作上限100,000,000、总行数100,000；内部 `SqlSiteLimits` 可以降低、不能提高或设为零。一次 SQL 可能多次调用 xFilter，限制是每次扫描而非整条 SQL。合法 SQL 不需要访问表时（例如 WHERE 0）不要求扫描，SQL LIMIT/EXISTS 若访问此表仍先完成本次扫描。

可选 `SqlCancel` 回调在执行查询的线程同步调用，必须 `noexcept`、不可重入该会话，context 必须存活到查询返回；若由其他线程发出取消，其共享状态须线程安全（例如原子变量）。查询开始前、返回行期间与最终提交前检查；SQLite progress callback 约每100条虚拟机指令检查；native 收集器在方法边界与逐事件发布处、解码器在指令和大循环检查点检查。取消返回 `SQLITE_INTERRUPT`，不能发布暂存结果；错误、取消与完成的并发瞬间按最后一次检查结果决定。检查点不保证 SQLite prepare 或单个解码操作实时可抢占，也不保证墙钟时间或系统调用及时结束；整个会话仍需单线程使用，回调之外不能并发调用其方法。

旧二参 `open` 和旧 `query` 重载保留并转发到默认限制及无取消回调的新实现；该兼容性仅针对草稿内部接口，尚未声明稳定公共 ABI。

内部 `query_scoped_bound` 支持 0–256 个按 SQLite 参数索引从 1 开始排列的 `SqlParameter`，类型限 NULL、64 位整数和 TEXT；`query_cursor_scoped_bound` 对同一参数列表提供严格提交后的分页。数量须恰好等于 SQLite 报告的最大参数索引；重复命名参数共享一个索引，`?NNN` 的空洞也须在列表中占位，值不参与 SQL。所有 TEXT 的总字节数不得超过本次 `max_bytes`，并以显式长度及 `SQLITE_TRANSIENT` 绑定；调用者须在同步调用期间保持输入稳定并提供 SQLite 预期的 UTF-8。空 TEXT 与 NULL 分开，嵌入 NUL 按显式字节复制，但 SQLite 对含 NUL 字符串表达式的语义不作额外保证。其他参数类型、数量不匹配、取消及预算失败不替换输出；旧可选单 TEXT 接口保持原有签名及行为。此参数字节限制和返回行逻辑字节限制分别检查，不代表 SQLite 或进程总内存上限。

所有表的文本由 UTF-16 编码为 UTF-8，以显式长度交给 SQLite，字符串中的 NUL 不会被 C 终止符截断；不使用会把开头 U+FEFF/U+FFFE 当作字节序标记的 SQLite UTF-16 入口。如果实际访问的文本包含未配对代理项，则返回 `SQLITE_MISMATCH` 而不提交部分结果；SQL 若不访问该列，则不触发转换或错误。转换前先计算 UTF-8 长度并对照会话当前 SQLite 单值长度上限，超限时返回 `SQLITE_TOOBIG`，不会先分配该临时缓冲。临时 UTF-8 缓冲与 SQLite 自身一样未纳入 Engine 总账本；单值长度上限不是进程或所有内存的上限，SQLite 排序和所有文本边界尚无完整兼容性证明。原始 MUTF-8 字节、接口边等其他表尚未实现。

会话在内部注册十三个模块；若中途失败，内部关闭连接。`close()` 仅使用 `sqlite3_close`，成功返回后才释放会话最后的 Dataset 引用，避免借用 lease 的最后一次 release 在 SQLite db mutex 内执行；不提供 `close_v2`。如 SQLite 返回 BUSY，会话保留连接和 Dataset，可在内部测试解除未完成语句后重试；若析构时仍不能关闭，草稿选择保留该连接与 Dataset，避免不安全释放，可能泄漏，生产协议尚未解决。

内部 `query` 在 prepare 前安装保守 authorizer，仅允许 SELECT、READ、RECURSIVE 及函数 count/sum/like/zeroblob，拒绝其他函数（包括 sqlite_log）、PRAGMA、ATTACH/DETACH、事务与写操作；只接受单个只读语句及零或一个文本参数，限定 SQL 长度、行数、逻辑结果字节数和列数；仅返回 NULL、整数和文本，其他结果类型明确拒绝。输出先暂存，step 和 finalize 都成功后才替换调用者输出；这是局部实现，尚未证明完整严格提交协议。绑定前拒绝超过逻辑字节上限的文本参数，并在查询期间限制 SQLite 单个字符串/BLOB/行长度；查询设置每约100条虚拟机指令回调一次的进度预算，允许指定数量的完整进度区间，第 N+1 次回调中断且不提交暂存结果。回调频率为 SQLite 的近似值，并不限定所有 prepare/step 内部开销、总内存或墙钟时间；查询结束恢复连接原限额并移除回调。该桌面草稿将 SQLite 编译为 `SQLITE_TEMP_STORE=3`，使临时表和索引驻留内存；这不是进程内存上限，也不保证所有 SQLite 文件类别都不会产生。本候选以单独翻译单元把固定 SQLite amalgamation 的上游 API 编译为内部链接，仅由适配器所需的私有包装调用；编译期检查列举的已知宏：拒绝覆盖 `SQLITE_API`/`SQLITE_PRIVATE`、额外初始化钩子、自定义头文件、测试钩子以及 `SQLITE_OS_OTHER`、`SQLITE_OS_KV`、`SQLITE_OMIT_WSD`，并要求既定线程、临时存储及自动初始化选项；这不代表检查了未来或未列举的所有 SQLite 编译配置。该编译/链接模型下，连接不会使用同进程另一 SQLite 实例的 auto-extension、默认 VFS 或日志配置，也不会重置或修改宿主实例的注册表。同进程两实例的定向对照和 Windows MSVC 对象符号检查覆盖这一模型；这不是进程沙箱，不防任意原生代码篡改，也不证明其他平台或外部替换链接配置。SQLite 内存及会话容器未纳入 Engine 总账本，逻辑字节上限不是 RSS 上限。Engine 停机/取消、并发和关闭竞态、系统 OOM、spool 与分页均未完成；不得用于生产或对外发布。

测试以固定原创 DEX 的人工模型建立同版本普通 SQLite 表，比较保留顺序或多重集的查询；这是有限样本，不构成 S01–S11 全部通过或设备运行证明。 迭代79补充空 IN、固定 JOIN 可用性、外连接、NULL 排序、文本 LIKE/ESCAPE 与 collation、复合身份及投影读取的有限对照；按需 xColumn 不等于 colUsed 下推，详细范围见 [逐项审计](../evidence/iteration79/audit.md)。

## 输入、来源 occurrence 与快照目录（迭代 34 候选）

新增 `dmg_snapshot`（每会话一行）、`dmg_inputs`（每个有序输入一行）和 `dmg_sources`（每个展开 DEX occurrence 一行）。三者只读；输入表的 `input_index` 与来源表的 `input_index` 可连接，来源表的 `source_index` 可连接各实体和使用点表，不能用相同内容摘要合并不同 occurrence。资源 APK 即使没有 DEX 仍保留输入行但没有来源行；APK 的来源按 DEX 数字序展开，`archive_entry_index` 保留 ZIP 中央目录位置，而不是 source_index。原始 DEX 的 archive SHA、条目名及条目索引是 NULL；其 `crc_verified` 和 `header_consistency_verified` 为 0，表示未作这两项归档检查。条目来源的两个状态按实际记录返回。

`dmg_inputs` 列为 `input_index, format, slot, role, slot_hex, role_hex, source_sha256, content_id, input_bytes, source_count, allow_no_dex, expected_digest_verified, container_metadata_checked`。`dmg_sources` 列为 `source_index, input_index, slot, role, slot_hex, role_hex, source_sha256, content_id, occurrence_id, logical_dex_id, dex_bytes, dex_version, archive_sha256, archive_entry_name, archive_entry_index, crc_verified, header_consistency_verified, expected_digest_verified`。摘要、content ID、logical DEX ID 和 occurrence ID 的域与 [来源身份契约](source-set-v1.md) 一致；只代表静态输入，不代表运行时 ClassLoader 绑定或来源可信认证。

`dmg_snapshot` 列为 `snapshot_id, namespace_key, namespace_hex, scope_complete, input_count, source_count, input_bytes, dex_bytes, string_count, type_count, class_count, method_ref_count, method_definition_count`；计数按 occurrence 累加。旧会话入口拒绝来源范围不完整的快照；显式 `open_scoped` 可接纳且如实返回 0 或 1，这只表示调用者的范围声明，不证明实际运行时没有其他来源。三个表的 rowid 分别是 input_index、source_index 和 0，均仅在当前表和快照内使用。

C ABI 的 slot、role 和 namespace 是以 NUL 结束的字节，不要求合法 UTF-8。其 TEXT 列仅在实际读取时严格验证 UTF-8，无效时返回 `SQLITE_MISMATCH` 且不提交部分查询结果；对应 `*_hex` 始终是小写十六进制 ASCII，保留原有全部字节，可在不读取 TEXT 列时检查任意字节身份。合法 UTF-8 中开头 U+FEFF/U+FFFE 与补充字符保持原值。转换输出按当前 SQLite 单值长度限制检查；hex 临时缓冲和 SQLite 内存未纳入 Engine 总账本。归档条目目前按 canonical `classes*.dex` 选择，条目名为 ASCII；不承诺其他 ZIP 名称的文本编码。查询仍由 SQLite 执行残余条件、连接、排序和 LIMIT，不实施约束或排序下推。

测试覆盖同字节不同 slot、资源-only APK、ZIP 中中央目录反序但按 `classes.dex` / `classes2.dex` / `classes10.dex` 展开的输入、完整性状态、普通 SQLite 物化对照和由原始 DEX/APK 字节独立计算的 SHA、Occurrence 与 Snapshot 身份；另对合法 BOM 标量、无效 UTF-8、十六进制回退及长度上限做固定反例。仅在所记录的 Windows MSVC 构建范围内验证，SQLite catalog 与全部生命周期/资源/生产提交协议仍未完成。



## 显式范围结果（迭代 35 内部候选）

`SqlSession::open_scoped` 是独立的显式入口，接受完整或不完整来源范围。它返回的会话只允许 `query_scoped`；调用旧的裸 `query` 返回 `SQLITE_MISUSE`，避免调用方无意丢失范围标签。旧 `open` 及 `query` 行为不变：不完整快照仍拒绝，旧会话调用 `query_scoped` 也拒绝。新接口仍要求原有来源生命周期、单线程和所有查询/取消/预算约束。

内部范围会话也可使用严格提交后的有界分页游标，见 [sql-cursor-v1-draft.md](sql-cursor-v1-draft.md)；它不是流式 provisional 或磁盘 spool。

成功的 `SqlScopedResult` 同时返回 SQL 行、不可变 `snapshot_id`、输入与来源计数，以及 `source_scope`：`partial_source_scope` 表示来源声明不完整，`declared_complete_source_scope` 只表示调用者声明完整，不代表已发现真实应用或 ClassLoader 的所有来源。成功只表示 SQL 语句在当前快照中执行并完成 finalize，不产生全局存在、缺失、唯一或业务决策。特别地 `COUNT`、`NOT EXISTS`、聚合、排序和 LIMIT 可能随添加来源改变；partial 的 SQL 行不能笼统当作全局结果的可靠子集。`dmg_snapshot.scope_complete` 与结果标签来自同一不可变 Dataset。

结果与所有标签先在私有临时对象构造，语句、finalize 和最后取消检查全部成功后一起替换输出；SQL 错误、预算、取消或内存失败保留调用者原结果。结果是复制值，可在快照或会话关闭后读取；结果、SQLite、转换缓冲及线程内存不包含在 Engine 总账中。此为实验性 C++ 内部接口；独立桌面 CLI 另有自己的单来源、同步协议，不提供稳定公共 C ABI 或 JNI，也不证明完整 SQL catalog、全部生命周期或真实设备行为。
