# 固定构件的桌面 SQL 原始采集器

`runner.py` 使用 Python 标准库实际驱动一次性 `dexmeguviz sql` 与同步 `dexmeguviz_sql_session`。它只产生原始观测，不计算加速比、显著性、通过门槛或 BIL A/B/C 结论。不得把桌面数据送入既有 BIL A/B/C 分析器并冒充三组结果。

## 运行前固定

配置必须固定两个 exe、原 `benchmarks/protocol.v1.json`、有序输入、SQL、参数、完整期望 rows 的原始 SHA-256，以及构件源码/工具链/构建标志、宿主与 Python 指纹、runner 文件摘要。相同路径内容变化立即停止，失败 campaign 不替换任何轮次。路径相对于配置文件解析；只执行这两个明确指定且已核对摘要的 exe，不执行配置内脚本或 shell。

两种模式显式传入相同 input/Engine owned/私有 SQLite heap 限额；每条查询使用相同 max_rows、max_result_bytes（共同上限1 MiB）、max_progress_intervals。相同工作流总超时约束两种模式；一次性模式每次请求新建进程，驻留模式在同一进程/快照内执行相同次数的查询。后台模式、不同线程策略、DexSQL 后端不混入本模型。

`expected` 文件只能是 `{"rows":[...]}`，使用实际 SQL 的完整单元格式：null、TEXT、`{"integer":"..."}`、`{"blob_hex":"..."}`。ordered 比较完整序列；bag 比较完整行的多重集，保留重复次数。不删列、不去重、不替换身份字段。one-shot 的 namespace 为 cli-v1，resident 为 resident-cli；这些事实进入 run identity，原始响应全部保留。若 SQL 本身读取 namespace/slot/snapshot 等而得到不同结果，比较失败，不能通过“归一化”掩盖。

驻留 ready 当前不含完整来源摘要，采集器执行一条明确记录的 `dmg_inputs` 身份查询，核对运行时 input_index/SHA/长度/slot/role。它在应用 SQL 之外单列计时、计数，并包含在整个驻留工作流成本中。一次性入口直接核对其响应中的 inputs 摘要。外部文件重哈希也单列 identity_check 原始记录，不冒充后端 query 时间。

## 命令与门禁

```powershell
# 只核对注册信息和写identity，不执行SQL程序；输出目录必须全新。
python benchmarks/desktop/runner.py --config desktop.json --out NEW_PREFLIGHT_DIR --preflight

# 仅自建小夹具：一组模式配对，每模式两条请求，无正式测量结论。
python benchmarks/desktop/runner.py --config synthetic.json --out NEW_CONNECTIVITY_DIR --connectivity

# 后续显式授权的正式桌面原始采集；本批未执行。
python benchmarks/desktop/runner.py --config frozen-desktop.json --out NEW_CAMPAIGN_DIR
```

预检产生 identity.json。正式采集还要求配置的 formal_runner_ready、冻结时间，以及独立正确性/生命周期门禁文件；门禁的 SHA、status=passed、complete=true、identity_sha256 都须匹配该 identity。采集器不会把门禁文件当作自己已经执行了全部门禁的证明。

采样数量沿用原协议的30轮、5组warmup、每快照10条查询；两模式顺序独立预登记为30组、各15次先执行，并明确保存在配置中。这是桌面双模式顺序，**不是**原 A/B/C 三元组的替代。warmup 与 measured 分开记录；异常、语义不一致、崩溃、超时、输出超限、源或构件漂移立即停止整组并保留部分 campaign，不删除慢值、不按显著性提前停止、不补跑替换行。

原 BIL 协议的正式条件会报告其旗标与必需字段是否齐备，但本 runner 不验证其中的设备、业务或 A/B/C 证据。它始终输出 performance_acceptance=not_evaluated、benchmark_conclusion=null、bil_abc_results=false，即使采集成功也不颁发性能结论。环境的热状态/电源等未由本工具测量，query 原始记录保持 environment_valid=null；后续分析必须另行完成这些预登记条件。

## 原始记录与计时

目录不覆盖、不删除。`records.jsonl` 逐条追加并 flush/fsync，包含开始、身份检查、查询、模式结束和失败；每个进程分别保留完整 stdout.bin/stderr.bin，驻留另保留 stdin.jsonl。summary.json 只写一次。线程并行排空 stdout/stderr，限制单行8 MiB、单进程stdout 128 MiB、stderr 4 MiB；超限即失败。独立超时观察者终止本次自建子进程，避免阻塞stdin/响应让采集器永久等待。没有自动清理缓存、旧输出或OS页缓存。

计时字段严格分开，缺失值为 null：

- `prepare_to_ready_ns`：驻留进程创建到完整ready响应被观察；一次性没有ready阶段，不能伪造。
- `source_prepare_us`、`session_open_us`：存在时保留后端自己报告的阶段；驻留 session_open 从最终 stats 读取。
- `statement_prepare_us`、`first_step_us`、`query_us`：native profile；未发生prepare时记null。first_step只是一次sqlite3_step耗时，不是首次答案延迟。
- `external_query_ns`：驻留 submit 到完整final响应被观察，包括协议成本；一次性不能从外部拆分该阶段，记null。
- `first_result_observed_ns`、`first_result_verified_ns`：从进程启动到完整SQL结果被观察/通过期望比较；没有业务first-answer观测，`first_answer_ns` 为null。
- `verify_ns`：本采集器比较完整rows的时间。`close_us` 是后端连接/会话close，不冒充全部Engine/进程销毁；驻留另记录外部close往返。
- `process_total_ns`：独立wait观察线程记录进程创建到退出；包含OS/观察调度，不是CPU时间。驻留只在模式结束记录一次，不摊造每条query的进程时间。`workflow_wall_ns` 包含驱动、验证、身份检查、协议及记录成本。

native微秒值与Python单调纳秒观测不可随意相加，尤其prepare已包含在query/进程总时中的部分不能重复计费。CSV、图表、RSS/PSS、缓存冷盘状态、收益区间和正式验收均不由此工具虚构。

本批仅在项目自建 raw DEX 上完成一组连通：相同32 MiB SQLite heap、输入/owned/结果/进度包络，验证完整int64、NUL文本、NULL、BLOB与来源计数。没有执行真实语料、正式30轮采集、性能统计、设备、ART、Hook或BIL操作。P3-05仍在进行中。

根复核修订：两模式的workflow计时和绝对超时均从首次外部身份检查之前开始；process_total仍单独按子进程计。驻留workflow包含最终transport收束，避免与一次性包络不对称。捕获线程失败由response轮询检查及时传播，线程启动失败会尝试终止/等待本次子进程；OS无法即时终止的异常不作实时保证。这些失败路径未在本轮做故障专项。
