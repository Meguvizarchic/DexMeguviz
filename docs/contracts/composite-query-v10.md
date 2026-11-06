# 组合查询 v10

当 inherited_fields、numeric_literals、interface_fields 和 use_streaming 中至少两项被谓词或显式 capability 使用，或者显式要求 `composite` 时，计划使用 capability 位 262144、profile `dex-query-composite-v10`，规范域 `DexMeguviz:QueryIR:composite-v10` 和 `query:v10:` 身份。v6 superclass-only 与 v8 interface-inclusive 不能同时使用：两套成员语义不同，混用返回 Unsupported；v11 与任何 v10 组合也返回 Unsupported；未开放的能力名称亦返回 Unsupported。`use_streaming` 仍必须包含 use scan；各谓词适用的实体种类、来源范围、作用域与三值规则沿用各自原契约。

组合不重写或合并原有节点和见证。继承路径、接口图、数值事实与 use 事件使用各自的 getter 与来源实体；按 operator/node 标识独立关联。Job 的 Batch 是 provisional，最终 coverage、decision 和执行状态须查看终态。启用 use_streaming 时，同步与 Job 均沿用 v9 的逐方法提交和工作计费规则；v10 的 Job 目前原子交付，混合见证尚未证明可安全提前交付。组合内所有工作共享 `max_work`、取消和中间结果上限，不能将 v9/v10 的预算轨迹与旧 v4 等同。

不使用组合能力的既有 v1–v4、v6–v9 查询维持原规范域和身份。该契约只覆盖静态查询，不证明 Android 加载、运行时绑定或完整 DEX 校验。
