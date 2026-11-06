# 显式输入范围的类注解 Job

`ScopedClassAnnotationQuery.start`（v24）及 `ScopedClassAnnotationStringQuery.start`（v25）要求显式输入 slot，返回含 `EntityJob` 行为和复制 `scope` 的 Job。slot 和 source 索引是启动时按调用方静态输入声明并展开的范围，空 slot、资源-only slot 和多 DEX 输入分别保留其含义；它们不认证签名、安装、ClassLoader，也不证明全部行已访问。Job 和复制范围可在 snapshot 关闭后继续使用。

每个非空 batch 交付前校验查询/快照身份、实际来源序列和候选来源；批次始终暂定。成功终态从求值器实际来源序列核对范围；失败、取消和 deadline 保留原终态，不伪造范围验证。调用方必须结束并发消费、读完批次，并在 EOF 后检查 terminal、executionStatus、coverage、decision 和 unknownRows。状态是获取时的计算及范围快照，不能证明正在并发或未来的批次已经成功交付；批次交付异常后必须丢弃该流。原非 scope Job 不接受 scope，旧范围同步入口不变。

实际来源序列仅对显式 scope 注解 Job 保存在 Engine control 账本中；预算/分配失败不会提交成功证明。为此所有 Job 的内部控制块新增一个小型 optional 字段，极紧预算条件下不保证与旧版逐字节内存行为相同。范围验证不是认证；真实设备、ART、BIL、性能及完整兼容仍需另行检查。
