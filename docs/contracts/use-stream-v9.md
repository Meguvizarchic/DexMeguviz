# 逐方法使用事实执行 v9

本profile仅在显式 `required_capabilities:["use_streaming"]` 且计划包含 use scan 时启用，capability 位131072，QueryID 使用 `query:v9:` 和 `DexMeguviz:QueryIR:use-stream-v9` 域。默认 v4 计划及其 QueryID、执行顺序和预算保持原有行为；未声明 use scan 时返回 Unsupported。与 inherited-v6 / numeric-v7 / interface-v8 混用时遵循 [v10 组合契约](composite-query-v10.md)；v5 尚未开放。

v9 同步与 Job 均以相同逻辑顺序对每个来源逐方法执行：完整 checked 解码和该方法全部原始 use 记录完成并计费，提交该方法的 scan progress，随后依序登记记录和计算当前 scan 谓词，再开始下一方法。局部 scanner 已消耗但尚未合并的工作与外层谓词已消耗工作，共同受同一 `max_work` 限制。方法未完整检查、超限、损坏或取消时，该方法不提交事件；已完成方法的事件可以作为 provisional 候选。

仅下列无排序形状可提前交付，其他 v9 关系仍采用相同逐方法计费但原子交付：三类 use 根 scan；invoke scan 的 filter 或 label→filter；以及 Exists 的 method_defs→invoke_sites caller join/semi-join、invoke_sites→method_refs target_ref join、两个 invoke scan 的 bag/set union、其 bag union 的 distinct、单个 caller join 的 group_by_owner。Unique 仅支持 max_results 至少2 的根 scan 或前述 filter/label 单链；Unique 的 max_results=1、重复风险的 join/union/distinct/group、排序及 TopN 继续原子交付。所有图候选仅在对应根行和所需子关系形成后交付。使用事实由 `(source occurrence, relation, caller ordinal, dex_pc)` 区分，已发布 Batch 保持来源和证据；未发布事件不能支持最终存在或非唯一结论。

相对于 v4，v9 的解码与谓词交错顺序不同，因此在相同紧预算或同源后续损坏时，错误首次发生的位置与 v4 可以不同，不得声称两者的预算/错误轨迹一致。同一 v9 计划的同步和异步执行须在相同工作额度下报告一致的执行状态；Job 已交付候选可在后续失败时保留为 Partial。内存分配、队列背压和消费者持有 Batch 可能使物理内存峰值不同，不能把逻辑 `max_work` 等同 RSS。

这不是完整 DEX verifier、运行时分派或 Android/BIL 证明。未覆盖的关系形状、全部算子统计及设备行为仍需验证；不得将整个 Q09 标为完成。
