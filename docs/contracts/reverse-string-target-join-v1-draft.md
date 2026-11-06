# 显式字符串反向 target_ref 连接（内部实验）

`dmg_query_execute_reverse_string_target_v1` 是独立同步 C 入口，只接受 v4 的直接 `join(target_ref, scan(string_uses), scan(string_values))`。方法和字段反向入口依旧拒绝字符串形状；逆向顺序、半连接、嵌套算子、高级能力、Job 和批量 opt-in 均明确拒绝，不回退。旧普通查询及 Job/批量不自动使用索引。

索引按同一 Dataset/source occurrence 的 string_id 查找真实 checked `const-string` / `const-string/jumbo` 使用点；纯字符串池、注解、静态初值不产生方法使用事件。同值不同来源不按内容合并，也不代表跨来源 `target_symbol` 或运行时绑定。

仅对所选 checked 前向事件与所选目标字符串的交集逐项核对；匹配缺失、字段不符或重复拒绝。未出现在左侧筛选结果的页记录会跳过，不逐条校验这些记录或整个索引；仍依赖索引对所请求来源和目标的正确性。成功结果保留原顺序、QueryID、PC、opcode、绑定、见证和 scope。两个直接 scan 成功完成后先检查各侧已选中间行数；任一侧超过4096返回 Unsupported 且 out=NULL，扫描期间更早的损坏、预算等错误优先。检查在空左侧判断之前，因此左侧为空且右侧超过4096也返回 Unsupported；空左侧不请求索引，但不保证成功。

沿用精确尺寸/版本的 `dmg_reverse_join_options_v1`，索引和适配工作受额外限额；错误 out=NULL，已建完整索引在后续物化失败时可能保留。额外工作与资源驻留可能改变内存峰值、预算阈值与错误/取消时点，不保证与独立查询阈值完全一致或性能收益。同步入口无外部取消回调；关闭后不接收入场。

固定样本与 C ABI/交叉构建不能代替完整 QueryIR、所有字符串和错误条件、动态取消、Android/ART、设备或 BIL 验收。
