# 候选方法有限 32 位数据流（内部实验）

该分析仅在调用方显式选择方法后运行；不影响默认元数据扫描，不提供公共 C ABI 或运行时绑定。输入 bytes 和 metadata 必须来自同一不可变、已检查来源。无方法体返回 `has_body=false`；含 try 的方法沿用默认 CFG 的 Unsupported，不近似异常分派。若普通 CFG 中结构可达路径落入 payload 或越过指令流，也返回 Unsupported，不交付部分结果。

默认分析仅接受可达块上的 nop、单寄存器 move、32 位 const、整数二元运算及其 2addr/lit8/lit16 形式、goto、if、switch、return-void 和单寄存器 return。其他可达指令（包括对象、宽值、堆访问、调用、move-result 和显式 throw）返回 Unsupported；不猜测别名、未知调用副作用或读取宽寄存器对。未到达块不产生 use 记录。此范围不代表完整 DEX verifier、类型检查、全部 opcode 或 ART 可执行性。

显式启用 `allow_opaque_invokes` 后，标准及 polymorphic/custom 的 invoke 按编码顺序记录各参数寄存器**字**的读取；range 形式逐字记录。调用是黑盒，不推断分派、参数类型、堆或对象内容、副作用、返回值、是否返回或异常路径。正常流中的 `move-result` / `move-result-object` 将目标置为 Unknown，`move-result-wide` 将目标及下一寄存器均置为 Unknown；其静态定义 PC 是该 move-result 的位置。此选项不验证 move-result 的位置或调用签名，也不将相邻两字合成类型化宽值。每个参数字都计分析工作量和 use 上限；默认关闭以保留旧拒绝行为。

每个寄存器的值格为不可达、已知 32 位比特模式或 Unknown；入口值均为 Unknown。合并点只有各结构前驱的值相同才保留常量，否则为 Unknown。每个 use 额外记录所有结构路径一致的单一最近定义 PC；入口或多个不同定义为 `no_single_definition`。即使不同定义写入相同常量，也只保留该常量而不声称唯一来源。所有结构边都参与合并，不根据条件值剪枝，故结构可达不代表路径条件可满足。

加减乘按 32 位补码环绕，位移距离取低 5 位；有符号除法和余数按 DEX 整数语义，包括最小整数除以负一。除数为零时输出 Unknown，未建模的抛出路径不作为正常完成证明。输出是寄存器读取时的局部位模式及来源证据，不覆盖精确 DEX 事实，不表示运行时行为或全程序 use-def。

每次分析独立受两次 checked 解码合计工作量、CFG 工作量、寄存器×基本块状态单元、分析工作量、use 数和取消限制；使用调用方 PMR，失败不返回半成品。预算不是进程 RSS 或总延迟承诺。固定自造 DEX、独立字节 oracle 与 Windows Debug/ASan 定向测试的证据仅覆盖记录的样本。

## 显式保守寄存器模式

`Options.allow_conservative_registers` 默认 false。启用后，在既有整数分析基础上接受常见 move-object/move-wide、宽 const、对象/类/字符串/方法常量、monitor/check-cast/instance-of/new/array-length、filled-new-array/fill-array-data、字段与数组读写、wide/object return、显式 throw、比较、数值转换、浮点与宽整数算术。invoke 仍单独要求 `allow_opaque_invokes`；保守寄存器模式允许 move-result 和 move-exception 写 Unknown，但不验证其位置或类型合法性。

值格仍是每个寄存器字独立的 32 位比特模式，未新增对象类型、堆或宽值格。宽 const 精确拆成两个字，宽 move 先读取两个源字再写两个目标字，以保留重叠 move 的语义。对象 move 保留已知的字比特（例如来自 const 的零），不把它解释为真实对象地址。整型 neg/not 和 byte/char/short 窄化按32位位模式计算。字段/数组读取、对象创建、引用常量、浮点/比较/其余转换及宽算术的目标统一写 Unknown；宽目标两字都写，不能保留旧高字常量。字段/数组写入只记录源字和对象/索引读取，不凭空改变无关寄存器，也不建立别名或堆事实。

`Use` 继续逐字记录 `(pc, register, operand, definition_pc, constant_bits/known)`。wide 操作读取两个相邻字；long shift 的移位量只读取一个字。每次 register write 的定义位置是本指令 PC。相同常量来自不同定义时，值可知但 definition_pc 仍不可唯一。结构路径与参数字全部保留，不推断类型、分派、可达条件、ART 合法性或运行时数值。

## 显式异常路径

`Options.include_exception_edges` 也是默认 false，且必须配合保守寄存器模式。启用后复用 CFG 的已检查 try/handler 边。每个受保护基本块向 handler 传播的状态是**块入口及每条指令完成后状态的逐寄存器 join**，覆盖块内每个指令边界；绝不只用块末状态。没有通过 may-throw 分类删去边界，因此可能把不能实际抛异常的指令边界也包括进来，精度会下降但不会伪造跨所有可能入口的常量。handler 的 move-exception 将对应目标写 Unknown。普通后继仍接收正常块末状态。

异常状态不提供运行时 catch 类型/顺序分派、方法外传播或堆状态模型；继承 CFG 的保守过近似。`Result.exception_edges_included` 与普通 reachable_flow_complete 分开。异常模式额外为两份寄存器临时状态预留 state-cell 上限，并对每条指令边界的寄存器 join 计分析工作；失败不交付半成品。未启用新选项时保留既有拒绝行为。

## 桌面入口与本批边界

默认关闭的 `DMG_BUILD_DATAFLOW_TOOL` 构建 `dexmeguviz_dataflow INPUT.dex METHOD_ORDINAL [--conservative] [--opaque-invokes] [--exceptions]`。入口实际读取并检查 DEX、选择定义序号并执行分析；输出模式、假设、work 和所有读取证据。单输入64 MiB、工具PMR 256 MiB、uses 100000，不能把这些限额当进程 RSS 保证。工具只在桌面构建，不修改 Android 或默认扫描。

本批 Windows Release core/入口构建通过。两个基本样本覆盖宽常量/宽move、object move、float结果Unknown，以及 handler不能直接得到块末常量；另验证默认模式拒绝新增宽指令、未显式开启异常时拒绝try。样本是项目原始DEX的局部编码变体，经过当前reader/checked decoder，不证明ART/类型验证。字段/数组/所有转换的独立差分、完整异常/循环/取消/预算/故障/ASan 和真实设备专项仍待统一执行。P4-05仍为进行中，不能以此报告完整use-def或运行时分析。
