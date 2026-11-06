# ADR 0005 共享方法查询计划

2026-10-26。将JSON解析、类型检查、规范化和执行放入公共核心，CLI与同步/Job C ABI共用；旧typed-method入口转换为同一Plan。该变更推进完整QueryIR，没有把方法子集改写为最终目标。

选择PMR树与显式typed nodes，避免第三方新生产依赖；JSON输入不承载运行时代码。临时解析树释放后Plan不借用输入。纯逻辑子树可规范化并有稳定node_id；SourceSet顺序与bag语义不随意去重。

先提供可审查的标量执行器：按方法需求闭包解码一次，使用可验证的指令见证和完整性状态。TopN使用有界heap并完整扫描所需范围。reference结果先成形再发布；后续优化计划必须与之差分，不能为了快而改变否定、作用域或基数语义。

root关系暂限method_defs，完整类/字段/ref关系、Join/SemiJoin、owner分组、有界展开和真正Union/Distinct继续属于原任务。reflection flags、call-site bootstrap符号等未支持条件明确拒绝。

当前QueryID规范化绑定预算与投影，跨同Engine Snapshot复用仍按实际scope解析；缺失slot不是空关系。Result/Batch持有Plan以解释见证，释放Job不使query_id悬空。
