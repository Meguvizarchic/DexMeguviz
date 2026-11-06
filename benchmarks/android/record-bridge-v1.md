# TaskProbe 单次记录桥（实验）

`ProbeRecordBridge.record` / `jsonRecord` 将一次 `TaskProbe.Result` 与调用方显式提供的事实转换为 `tools/analyze_benchmark.py` 可读取的单条 record。输出并非完整 campaign：调用方仍需显式构造顶层 protocol SHA、实际 run_identity、campaign ID、所有 A/B/C 行及独立外部门禁证据。本组件不计算或认证身份摘要、不运行后端、不认定正确性，不提供设备操作或正式性能结果。

输入 `facts` 为只读期间不变的 Map，按 analyzer 字段提供 `case`、`phase`、`triplet_id`、`backend`、`order_position`、`identity_sha256`、`backend_build_identity`、`execution_complete`、`status`、`correctness_passed`、`projection_sha256`、`environment_valid`、`exclusion_reason`、`counters`、`warm_query_ms`、`warm_query_samples_ms`、`foreground_frame_times_ms`、`foreground_capture_complete` 和 `post_close_residual_bytes`。所有事实必须来自实际调用方；桥不会把缺失状态、身份、正确性、环境、暖查询或关闭后残留假定为成功。分析器当前对所有case要求 warm_query_ms 和 post_close_residual_bytes；未测量时传 null，将保留并阻止完整标记。

桥重核采样线程已结束、错误为空、31项基线、全部计划采样位、边界、原始与范围内样本一致性、峰值和计时包络；缺失或异常令 `complete=false`。`probe_evidence` 保留失败类名、漏采、原始时间/PSS、在途及跨边界样本；无法得到的指标输出 null，原始证据中的 -1 保留。调用方显式传入的失败/环境/正确性值保持原状，分析器仍按自身协议核验。调用期间不得并发修改 facts 或 Result 数组；JSON 仅接收有界 Map/List/字符串/布尔/有限数值，不写文件、不联网。

本桥不会证明输入事实真实、APK/设备身份、runtime/Hook正确性、性能优势，且不涵盖完整 warm/前台数据采集。现有验证为 Java 8 主机合成控制，以及带420条合成数据的 analyzer 解析/拒绝缺身份对照；无 Android/ART、真实 DexKit/BIL 或性能结果。
