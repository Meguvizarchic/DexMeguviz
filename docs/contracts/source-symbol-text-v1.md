# 来源局部符号文本 v1

`dmg_snapshot_copy_symbol_text_v1` 解析单一静态 DEX occurrence 的 string_id、type_id 或 proto_id，复制 UTF-16 code units。调用方必须持有快照引用，提供 1–1048576 的字符上限；`out=null,capacity=0` 只查询长度，带缓冲调用要求容量至少等于长度，失败将长度置零且不写输出。无效来源、种类或索引返回 InvalidArgument，超预算返回 BudgetExceeded，关闭快照返回 Closed。type_id 解析为其描述符，proto_id 解析为方法原型描述符；均不表示类型被加载或定义。两次调用之间必须保持相同快照且遵守借用输入不可变约定；调用方提供的输出缓冲与 out_length 须有效可写且不得相互重叠。

Android `DexSourceExport.stringAt/typeAt/prototypeAt` 和 Kotlin 对应方法在快照监视器内复制结果，返回独立 String，可用于解析 annotation `EncodedValue.STRING/TYPE` 的来源局部索引；显式字符上限应用于 UTF-16 单元数。Java 字符数组和 String 不记入 native 引擎内存预算，且本接口同步执行。不能将静态文本等同于 ClassLoader 来源、运行时对象、完整 annotation matcher 或 DexKit 等价性能。
