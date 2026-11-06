# C ABI 契约

头文件 `include/dexmeguviz/dexmeguviz.h` 是当前可调用接口；预发布 ABI 版本1。尚未宣称稳定 ABI；options/query 的 struct_size 当前要求精确相等，ABI版本不符拒绝。后续新增布局需要明确兼容方案与旧C消费者测试，不默默复用当前版本。

Snapshot/Result 是 opaque handle。所有调用期间由调用者保持有效引用；retain/release成对，NULL释放无操作。任意伪造指针、释放后使用、重复release不在契约内，不声称能验证任意损坏地址。

Snapshot open_copy 同步取得自有字节并建立声明目录。close 使用原子 admission 标志拒绝之后的新查询；已通过admission的同步查询可继续。release只释放引用。不同查询可读同一不可变Source；每次同步查询有独立临时状态和Result。

Result共享Source并自有候选文本。Result在Snapshot close/release后仍有效；getters返回借用视图，直到相应句柄最后release之前有效。不得持久化这些指针；持久身份使用结果中的ID。

公共结构只包含固定宽度整数、C指针和显式长度，无STL/C++异常/Java对象。文本为uint16_t单元；内部char16_t数据经值复制，避免不同类型的指针别名读取。错误消息写入调用方的固定256字节buffer，不分配共享thread-local错误对象。

稳定错误枚举见头文件：InvalidArgument、CorruptInput、Unsupported、BudgetExceeded、OutOfMemory、InternalError、Closed、SourceMismatch。open/query在所有失败路径将out置NULL，C++异常在API边界转换，无法恢复的硬件/进程错误不假装可捕获。

当前已提供Engine、typed compiled Query、独立Job/Batch、取消/deadline和有界队列。Query仅在所属Engine内跨Snapshot复用，跨Engine需重新编译。Engine shutdown关闭admission，可选择请求取消；等待超时不取消。Job最终release请求取消并join自己的worker；已交付Batch继续有效。详情见execution-v1.md。

新增接口保留原ABI1结构与原同步C消费者；没有改变原结构布局。JSON方法计划通过compile_json/execute或Job执行，并有query_info、profile、scope和witness getters。Result/Batch保活Plan，未投影文本须按projection_mask解释。完整关系IR、Android导出SO及全P1-09门槛尚未关闭。

SourceSet新增函数族使用独立结构，不扩大旧输出结构。旧snapshot_get_info/result_get_source仅在逻辑DEX数恰为1时可用，否则Unsupported；overview/input/source/origin新getter明确有序输入、资源包与候选来源。所有getter借用字符串仍由Snapshot/Result/Batch owner保持。身份升级与scope规则见source-set-v1.md。

实体扩展新增独立的entity row、relation info和relation job status结构，通用getter要求准确out_size，错误不写输出。旧方法result/batch getter与旧job状态/wait对非method_defs返回Unsupported，防止把引用/类/字段行解释成方法定义。QueryID、profile、scope、witness与origin getter保持通用；Batch可直接调用Result的新getter。未知属性用known位，根Unknown累计在relation info的unknown_rows；细节见entity-query-v2.md。

关系对象入口新增binding、relation witness、graph info与operator profile输出。所有关系对象都拒绝旧方法Result/Batch/Job接口，即便输出类型为method_defs。新getter按准确out_size检查，绑定文本、标签和profile在Result/Batch中保活。Scan统计域与主结果行数分开，终态及证明范围见relational-query-v3.md。fuzz证据只适用于其记录的源码和目标。

Join扩展新增绑定路径、SemiJoin证明绑定及其路径、左右端点link getter；带尺寸的输出严格核验out_size，原结构布局保持不变。Result/Batch保活完整绑定与证明文本、路径和连接端点。关系执行fuzz在本轮此前的v3源码上已运行；新增Join需单独验证，不能复用该结论。

继承查询的新增独立 `dmg_inherited_witness` 和精确尺寸 getter 保持原 `dmg_witness` 布局；作用范围与未知边界见 [inherited-query-v6](inherited-query-v6.md)。

实验性同步 C 多规则接口使用独立版本化选项和批次句柄；结果物化、引用、失败原子性、并发与资源边界见 [multi-query-c-v1](multi-query-c-v1.md)，不构成稳定 ABI 或完整 P2-01 验收。
