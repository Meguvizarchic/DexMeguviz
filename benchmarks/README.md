# A/B/C 基准协议草案

P0-08 当前为 **in_progress**。`protocol.v1.json` 固定了比较对象、统计方法、相对净价值门槛及失败处理，但正式设备、精确 APK、A/B/C 构件、前台脚本和绝对容差尚未选择。29 个待选字段保留 `null` 并登记在 `required_before_run`；`formal_runner_ready=false`。本目录没有正式手机 runner，也没有真实性能结果。

`benchmarks/android/` 包含独立、实验性的单任务 Android 耗时与 PSS 采集组件；它不构成正式 A/B/C runner，尚未在设备验证，也不会自动生成完整分析器输入。

## 已固定的比较口径

- **A**：固定 BIL 的真实 DexKit 2.3.0 用法，一次 `resolveAll` 共享计划，每个 archive 建一个 bridge；不能人为改成逐规则开 bridge。
- **B**：同一规则语义、输入、验真和产品结果投影下优化计划、生命周期与物化的 DexKit；必须冻结实际优化 patch。
- **C**：相同产品请求与资源包络的 DexMeguviz。源码、构件、配置和完整 runtime profile 必须绑定；metadata-only 原型不作为完整 BIL C。

三组都输出 A→B、A→C、B→C，不能把 A→B 的改进记作新内核收益。共同结果按接受后的 Method/Class/角色组描述符及状态比较，保留 relatedClasses 关系；A/B 没有原生 PC 时不补造原生证据。C 的完整事实 golden 单独验收。

每个配置、每个 case 固定 **30 个 A/B/C 三元组**，即每个对照有 30 个 matched pairs。种子 `20261026` 将六种执行顺序各重复五次后打乱，JSON 已保存完整顺序表；每个 case 先做固定五组三元组 warmup，原始记录也保留。设备、APK、ABI、页大小、预算、功能配置和缓存模式不能混池。

## 指标和门槛

主耗时为 `full_task_ms`。从昂贵准备前 admission marker 开始，包含原生库加载、强身份、快照复制/解压/解析、查询、业务验真、转换、必要缓存落盘和同步释放，直至成功产品结果提交及必要清理完成。prepare、first answer、warm query、close 单列；first answer 是累计时间，不与其他相位简单相加。

主内存为 `observed_incremental_peak_pss_bytes`：完整任务期间观察到的目标宿主进程 PSS 最大值，减去 admission 前 31 次采样的中位数，最低为零；固定 10ms 采样，并保留采样时间和缺失计数。这是采样峰值，不能冒充 allocator 精确峰值。controlled owned allocations、RSS/PSS、CPU、字节量、code units、索引构建次数、JNI 批次和释放后残留分别保留，不互相替代。

两项净价值诊断预先定义并分别报告：

| 路线 | B→C 判据 |
|---|---|
| 主耗时路线 | 完整耗时配对比值的 95% CI 上界 ≤ 0.85，即至少下降 15% |
| 备选内存路线 | 主内存比值的 95% CI 上界 ≤ 0.75，且完整耗时比值上界 ≤ 1.05 |

正确性、生命周期、双使用方复用、完整 L0、warm、前台等门禁通过后，总体验收还要求主耗时和内存两项阈值同时达标。 此外，C 相对原始 DexKit A 的冷适配 `full_task_ms` 和 `observed_incremental_peak_pss_bytes` 两项配对比值的 95% CI 上界均须严格小于 1.0；等于 1、不可估计或缺失均不通过。既有 A→C 25%/30% 目标仍仅为探索性报告。即使内存诊断通过，只要主耗时不达标，总体验收仍不通过。两个 95% CI 分别报告，不声称联合 familywise 95% 覆盖率。

分析器中的 `route_eligible` 仅表示该项阈值及数据完整性满足，可与总体未通过同时出现；`both_thresholds_met` 只表示 B→C 两个净价值阈值均满足，`original_dexkit_superiority` 单列 A→C 耗时及内存判定，完整结论仍以 `overall_acceptance` 及其余门禁为准。旧输出字段 `campaign_eligible` 已改名，不应与新字段混用。

此变更改变协议摘要与验收语义；新分析器只接受显式声明 `time_and_memory_all_required_scenarios_v3` 的协议。保留历史原始记录和结果；旧协议运行应保留其原协议及分析器版本，不得将旧判定冒充新规则结果，也不得对已观测的正式 C 结果事后改门槛。这里的判定只针对登记的设备、输入和场景，不证明所有设备的性能或兼容性。

统计估计采用配对比值的几何平均：对每个三元组计算 `log(to/from)`，取均值后指数变换；bootstrap 以完整三元组为重采样单位，10,000 次，种子 `20261027`，双侧 percentile 95% CI，分位数使用 `(n-1)*q` 线性插值。另报各后端中位数。零内存分母标记不可估计，不产生无穷大收益。

最终验收另要求完整 L0 耗时、snapshot warm 查询耗时和前台帧 p95，在 A→C 与 B→C 的配对平均差（C 减基线）95% CI 上界均严格小于 0；相等、缺失、不可估计或容差内变慢都不通过。此门槛仅覆盖登记的具体设备、输入和场景，不能推断所有场景。原先的绝对容差结果仍按登记值单独检查并报告，不得代替该严格门槛。

完整 L0 与 snapshot warm 的绝对回归容差、前台 p95 绝对容差、释放后残留容差仍为 `null`。这些值须根据产品要求、计时分辨率或仅 A/B 的校准在正式 C 数据前选择；同时比较 A→C 与 B→C 的配对平均差区间上界。L0 必须满足 native load/hash/source open/scan/index build 计数全零。warm 每轮保留 10 次查询耗时。前台 p95 每轮至少需要 1,000 个完整脚本帧样本，以每轮 p95 做配对统计；v1 不接受 p99 发布门槛或声明。

## 冷暖、失败和重跑

必需 case 为 cold adaptation、完整 L0 命中、已打开 snapshot 的 warm query、固定前台脚本并发 adaptation。持久事实缓存命中是启用该能力后才必需的独立 case。结果缓存 miss、native 未打开、OS 页缓存状态分别记录；强停 App 不等于清空 OS 页缓存。

所有 raw 行包括 warmup、partial、失败、取消、超时和环境排除均保留。某成员失败时整个三元组不能进入成功性能统计，但失败行、配对分母和原因仍在报告中；任何正式失败、缺失或排除都阻止本 campaign 获得验收。禁止删掉慢值、统计离群值或对某后端不利的值。

固定运行 30 组，不按显著性提前结束。身份漂移、语义错误、crash、预算超限或预定环境条件失效应立即停止并保存部分 campaign。定位原因或条件改变后另建关联旧 campaign 的新 campaign，重跑受影响 case 的完整 30 组；不能在旧 campaign 中用新行替换失败行。

## 原始数据分析器

`tools/analyze_benchmark.py` 只使用 Python 标准库，不执行目标程序。原始输入顶层包括：

```text
schema_version=1
data_kind=real | synthetic_control
campaign_id
protocol_sha256（protocol.v1.json 原始字节 SHA256）
identity（与 protocol.run_identity 完全相同）
records（全部 warmup 与 measured 行）
external_gate_evidence（独立运行时/资源/复用门禁证据文件引用）
```

每行包含 case、phase、triplet_id、backend、顺序位置、identity_sha256、backend_build_identity、complete、status、correctness_passed、projection_sha256、environment_valid、exclusion_reason、metrics、counters；warm/foreground case 还需原始查询/帧时间。完整字段见 protocol.raw_schema。identity SHA256 使用 UTF-8、键排序、紧凑分隔符的规范 JSON；构件身份必须逐行匹配当前后端。

```powershell
# 本轮已运行：仅合成小输入，验证分析器行为。
python tools/analyze_benchmark.py --self-test --write-draft-evidence docs/evidence/benchmark-protocol-draft.json

# 后续有真实 raw 且协议已正式冻结时使用；本轮未执行此命令。
python tools/analyze_benchmark.py --protocol benchmarks/protocol.v1.json --raw <raw-results.json>
```

分析器拒绝 `complete=false`、非 ok、正确性未知/失败、错结果投影、身份漂移、重复配对、非有限指标和未登记排除；保留失败数量、所有输入行总数、缺失行和原因。它不修改 raw 文件。匹配已有外部门禁文件时重新校验文件 SHA256、complete/status 和 identity；这只确认输入证据一致，不能证明分析器曾运行那个外部门禁。

合成控制测试使用 200 次 bootstrap 控制运行时间，正式协议仍固定 10,000 次。测试数字是人工构造，不能转述为 BIL 或 DexMeguviz 的性能。分析器不会从计时数据推断 APK 真伪、设备温度、PSS 采样真实性、Hook/UI 生效或外部门禁真实性；这些必须由选定 runner 和独立证据提供。

## 正式运行前仍需完成

选择并固定精确 base/split occurrence 及摘要、真实设备/系统/ABI/页大小、A/B/C 源码与构件、B 优化 patch、线程预算、功能/能力开关、预期产品投影和 runtime verifier、冷暖恢复脚本、前台脚本、测量实现、温度电量策略、OS 页缓存观察方式以及四项绝对容差。完成独立正确性门禁后，登记最终时间和协议摘要，才可以宣称 formal runner ready。当前材料保持 **P0-08 in_progress**。
