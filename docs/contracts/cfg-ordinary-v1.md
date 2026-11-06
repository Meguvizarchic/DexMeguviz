# 内部按需方法普通控制流图（实验）

`analysis::cfg::build` 在调用方显式指定单个方法和相同的不可变、元数据已检查 DEX 后，复用 checked decoder 的指令、goto/if 和 packed/sparse switch 事实构建基本块。普通指令的顺序边、无条件跳转、条件 taken/未取、switch 各 key 和 default 分别表示；return 和显式 throw 为方法内终结。重复 switch 目标保留每个 key，不推断条件可满足性或运行时行为。`build_checked` 仅供已持有经同一 reader 检查的 code_item、引用边界和 extent 的内部调用者使用，不能用它绕过快照身份或元数据检查。

图包括所有可解码的可执行块，保留结构可达标志；payload 绝不作为可执行块。落空到 payload 或指令流末尾以无目标的特殊边保留，而不猜测目标。只有从入口结构可达的路径均无此类缺口时，`reachable_flow_complete` 才为真；它仅指本契约所述的已建模方法内边，不等于 DEX verifier、ART 合法性或路径可行。无方法体返回 `has_body=false` 且无图；默认情况下含 try item 的方法仍在 checked decoder 验证后明确 Unsupported。

显式设置 `include_exception_edges` 后，按已检查的 try 范围边界和 catch 目标拆分基本块，为范围内每个可执行块连接其编码列表中的所有 handler。边携带该块的起始 PC、目标 PC、源局部 type_id 或 catch-all 标记及编码顺序。每个受保护块均连接 handler，是保守过近似：不判断块内指令是否会抛异常、类型是否匹配、处理器实际先后分派、运行时类解析或向方法外传播的异常。结构可达结果因此可包含不可能的运行路径。`has_exception_regions` 和 `exception_edges_included` 单独记录是否存在 try 及是否已请求这些边，不能由 `reachable_flow_complete` 推断异常分派完整。

构图按需调用，默认元数据及原 method facts 路径不构建 CFG。解码与图构建分别受工作上限、块/边数量和取消约束；vector 使用调用方提供的 PMR 资源，资源须比结果活得更久，失败和分配异常不交付半成品。`max_graph_work` 统计索引初始化、指令、目标、块、边及可达遍历的明示单位，不是 CPU 时间或进程 RSS 限额。输入字节和元数据须来自同一冻结来源；局部 PC 不是跨 DEX 身份。当前没有公共 C ABI、CLI、持久化或完整 CFG 能力声明。

固定自造 DEX、独立字节解析与 Windows Debug/ASan 样本的验证范围见对应证据；这不是完整错误注入、跨平台、精确异常分派、真实 APK、设备或 ART 验收。
