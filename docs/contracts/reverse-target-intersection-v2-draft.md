# 显式 target_ref 反向交集 v2（内部实验）

`dmg_query_execute_reverse_intersection_v2` 为同步实验性 C 入口，使用 `dmg_reverse_join_options_v1` 精确尺寸和 ABI 版本，只接受 v4 直接 `target_ref` 三类 use→同类本地目标 scan。反向方向、半连接、集合包装、流式、Job 和批量接线不支持，默认执行及三个 v1 入口不变；不是稳定 ABI。

前向 checked 扫描结束后，只对已选左事件与已选右目标同 source occurrence、本地编号的交集按目标域和 extra proto 去重请求反向页。普通 method_ref 与 method_and_proto 分别使用本身 extra；call_site 不匹配方法 target_ref。结果按原左/右顺序保留 QueryID、见证、Unknown、scope 及原逐对逻辑工作计费。仅逐项核对所选交集；未选择的页记录被跳过，仍依赖索引正确性，不代表完整索引或运行时绑定验证。

该入口不施加 v1 固定4096行限制，但仍受 QueryIR 中间行及结果上限、Engine scratch 账本和选项中的独立索引工作/字节/记录、适配工作及总页数上限约束。两个 scan 的损坏和工作错误先于适配；错误不返回半结果，但已完成索引在后续失败时可保留。同步入口无外部取消通道。额外内存、工作及检查点会改变紧预算阈值、错误先后和时机，不承诺与标量资源等价或性能收益。

固定 Debug/ASan 实验、真实 C 调用及双 ABI 静态构建证据见 [迭代103](../evidence/iteration103.md)，不能证明全面并发、真实系统 OOM、设备、ART、真实 BIL、完整 QueryIR 或生产性能。
