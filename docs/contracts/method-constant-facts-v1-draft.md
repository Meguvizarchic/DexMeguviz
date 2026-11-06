# 内部方法句柄和方法类型常量事实

显式 `instructions::Demand::method_constants` 仅提取 checked 代码中的 `const-method-handle`（0xfe）和 `const-method-type`（0xff）；每条记录保留方法内 code-unit PC、目标寄存器、opcode、方法句柄表或 prototype 表域及本 DEX 局部索引。重复指令保持各自记录。它不是调用、运行时解析、句柄目标或 bootstrap 行为；记录必须与同一不可变来源关联，不能直接把本地索引跨 DEX 联接。

遵循现有 decoder 的 035/037/038/039/040 接受范围，0xfe/0xff 在039之前返回 Unsupported；目标寄存器、局部引用范围与指令宽度仍先检查，损坏返回 Corrupt。提供新需求时每条输出额外消耗一个 validation-work 单位；原始指令工作、取消检查和 PMR 分配仍计入各自限额，失败不返回半结果。未请求时向量为空且 availability 为 not_requested，不意味着已读取为空；无 body 请求为 no_body，已检查的空向量才代表此静态集合为空。共享 FactsCache 保守拒绝该新需求，不复制未覆盖的列。

这是内部 C++ 能力，不增加公开 C ABI、QueryIR、JNI 或默认需求。DecodeResult 与 MethodFacts 的内部布局改变，使用方必须同源重编译；管理内存峰值及失败阈值可能改变。结构修改的合成DEX和固定主机样本不证明设备、ART或任何真实业务。参考 [AOSP Dalvik 指令格式](https://source.android.com/docs/core/runtime/dalvik-bytecode)。
