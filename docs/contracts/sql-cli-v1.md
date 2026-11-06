# 桌面一次性SQL与有序来源

显式DMG_WITH_SQLITE构建提供 `dexmeguviz sql INPUT --sql-file FILE`，可追加 `--source INPUT`、`--resource-source APK`；复用现有AUTO raw/APK、多DEX、有序occurrence和资源包空DEX规则。默认按普通CLI声明输入范围完整，`--scope-incomplete`可改为不完整；只是声明范围，不证明ClassLoader或全局不存在。`--expected-sha256`用于主输入，--budget-mib/--max-input-mib沿用Engine和输入缓冲独立额度。无SQLite构建明确Unsupported。SQL041仍拒绝。

SQL文件最多64KiB；可用--params-file指定最多64KiB、256项JSON数组，支持null、int64数字、UTF8文本、精确integer标签及小写blob_hex。浮点/布尔/多标签/未知标签拒绝，沿用私有SQLite只读authorizer及函数白名单；本入口不扩SQLite功能。

结果逻辑额度默认10000行/4MiB/10000个VM进度间隔，可用--sql-max-rows（≤100000）、--sql-max-bytes（≤4194304）、--sql-max-progress（≤1000000）设置。private SQLite heap默认128MiB，--sqlite-heap-mib可在1..4096内显式设置。原生site扫描还有独立预算，这些不是RSS或总延迟上限。

仅查询严格提交且SQL会话close成功后发布rows；SQL执行失败rows为空，sqlite_status和退出码保留。int64输出integer字符串标签、BLOB输出blob_hex，NULL与空值分开。有效UTF8文本按输出上限增量转义，不套用查询JSON的64KiB限制。完整JSON最多8MiB，序列化超限走原CLI的BudgetExceeded错误封套/退出3，不发布部分SQL成功结果；非法Unicode输出拒绝。语法/能力错误退出2，资源/中断退出3，内部错误退出4。

profile_v1 producer=desktop-sql：source_prepare_us含Engine创建、输入读取和Snapshot准备；session_open_us是SQL会话打开，query.elapsed/prepare/first_step来自既有SQL统计，close_us只测SQL会话close。first_step_us是首次sqlite3_step耗时，不是完整first-answer；SourceSet/Engine最终析构及JSON编码不在query耗时内，完整调用成本须由外层记录。

驻留程序也接受有序AUTO来源、resource-source、--scope-complete/--scope-incomplete、--max-input-mib/--budget-mib和--sqlite-heap-mib。默认保持不完整范围、累计32MiB输入；Engine额度512MiB。未传heap选项时保持原驻留行为，比较一次性/驻留必须显式对齐资源包络。任务id仍是字符串，旧JSONL请求/ack/close协议不变。

本轮Release与有限连通通过，完整S01-S11、并发/取消/资源压力及性能验收后置。DEX校验字段诊断请使用inspect，不作为SQL选项。

## 实验性元数据身份约束

一次性 `dexmeguviz sql` 以及同步/后台 `dexmeguviz_sql_session` 启动时可显式传入 `--sql-identity-equality`，为元数据表启用已有 `rowid`、`source_index`、`ordinal` 等值粗筛；另外传入 `--sql-identity-in` 才启用等值列的整批 IN。IN 开关必须与 equality 同时提供，重复选项、在非SQL命令使用或单独提供 IN 均拒绝。默认两个开关均关闭，旧入口和旧结果结构不变。启用时一次性 `profile_v1.plan` 给出请求的计划选项，驻留成功打开后的 `ready.sql_planning` 给出配置的选项；会话打开失败不表示选项已生效，选项本身也不证明查询实际一定命中下推。

仅处理 SQLite 声明为 usable 的约束、在 xFilter 接受实际参数；非整数值及超长IN按已有合同回退完整扫描。保留 SQLite residual、NULL、重复值及 bag 语义，不声明 omit、排序、LIMIT 或唯一性；目录和使用点表不因此下推。当前仍为实验性桌面功能，不进入Android，预算/取消触发时序可能与默认计划不同，完整S01–S11与跨平台验收尚未完成。
