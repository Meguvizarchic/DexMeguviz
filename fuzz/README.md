# 有界覆盖引导模糊测试

当前有六个开发目标：`dmg_fuzz_dex`、`dmg_fuzz_code`、`dmg_fuzz_archive`、`dmg_fuzz_query`、`dmg_fuzz_relational`、`dmg_fuzz_use_scan`。默认不构建，不进入 SDK 生产构件。原五个目标的种子和输入范围保持不变；Query 目标验证不受信 JSON 的编译、类型检查、规范化和资源回收，relational 目标执行能够编译的查询。运行入口：

```powershell
python tools/run_fuzz.py
```

脚本使用本机已安装MSVC/CMake，RelWithDebInfo动态Release CRT、`_ITERATOR_DEBUG_LEVEL=0`、`/fsanitize=fuzzer`与`/fsanitize=address`。MSVC的Debug预编译fuzzer使用iterator level 2，与预算可恢复的项目配置不一致，因此选择一致的Release CRT，并保留首次链接失败日志；没有绕过链接器ABI检查。

每目标10000次执行，固定种子20261026，输入上限65536字节、每输入超时10秒、过程RSS保护2048MiB。解析器/解码器/归档自身另外有managed分配与工作配额；Fuzzer进程限制不等于SDK的RSS保证。所有种子来自生成式公开可重建语料，不包含私人宿主APK。

DEX 目标走真实 C API，成功后查询并核对资源回基线；内部错误或残留使测试失败。code-item 与 archive 目标走对应核心及 PMR，意外异常、内部错误与资源残留使测试失败。

relational 目标使用 8 MiB Engine 托管内存限额。每次输入先编译 JSON，成功后才打开两个固定 raw DEX 来源：`left` 对应 `tests/fixtures/generated/definition_catalog/definitions.dex`，`right` 对应 `tests/fixtures/generated/method_facts/method-uses.dex`。CMake 在配置时读取这两份项目自有夹具的 HEX 与 SHA-256，在构建目录生成 `fuzz_relation_fixtures.hpp`；只有 relational 目标包含此头文件。来源打开时再次校验嵌入的 SHA，不读取或嵌入私人 APK。

执行成功后，harness 先释放 Snapshot 和 Query handle，再读取 Result 的实体、绑定、Witness、算子 profile 和来源信息，最后释放 Result，检查所有分配分类与 active jobs 回到初始基线。内部错误、失败时返回非空输出、读取器错误或资源残留会终止 fuzz。合法的无效输入、不支持能力、来源范围不匹配和预算失败按失败返回处理；带 `ResultLimit` 的部分 Result 也会被读取检查。

执行种子覆盖 scan、filter、union 的 bag/set、distinct 的 entity/tuple、label、group_by_owner、Join/SemiJoin，以及 Unknown 消除、Unique、TopN、中间行数预算和工作预算。这是在两份原始夹具上的随机执行和资源不变量检查，不是独立语义 oracle，也不覆盖尚未实现的完整关系 IR 或 BoundedExpand。

`use_scan` 使用不超过64KiB的变异DEX字节，先以独立的事实类 PMR 读取元数据；读取成功后分别扫描 StringUse、InvokeSite 和 FieldUse，source_index固定为0，每次扫描工作上限100000、结果上限4096，scratch与metadata共享8MiB托管预算。成功时逐行核对caller目录、code offset、PC、opcode、目标表索引和原始指令字节；普通method、method_and_proto和call_site分别验证各自引用域及extra proto。完整成功和受控失败的进度均检查已完成方法、无body、code unit与资源计数，最后检查账本归零。坏输入、明确的预算/取消/不支持及分配失败按受控失败处理，异常内部错误不能当成功空结果。

新目标的六份种子为原method_facts中的method-uses与invoke-domains-038、以及use_relations中的双调用、字段读写、普通/jumbo字符串和有效事件后坏opcode；每份固定SHA-256，在配置构建前后及复制语料时校验。该目标只 fuzz **单来源内部扫描器**，不证明公开事件根、事件Join、Android运行时或性能；实际轮次和结果以本轮日志为准。

语料变异和新增覆盖保存在 `build/host-fuzz`，命令、日志、种子清单和 summary 保存在 `docs/evidence/fuzz`。`seed-manifest.json` 使用 schema version 2：`targets` 保存各目标种子的 SHA-256，`relational_fixture_inputs` 和 `use_scan_fixture_inputs` 分别记录固定输入及摘要；同一输入信息还写入各自的 fixture JSON 和成功运行的 summary。配置和构建之间若夹具发生变化，脚本会中止，避免把不一致的来源登记为本轮证据。

此前五个目标各 10000 次运行退出 0，未发现崩溃或 ASan 报告；新增 `use_scan` 目标的结果以它实际运行产生的日志为准。有限运行不能证明无漏洞、完整格式正确性、设备运行或性能优势。使用的编译选项依据[Microsoft官方说明](https://learn.microsoft.com/en-us/cpp/sanitizers/asan-building?view=msvc-170)。
