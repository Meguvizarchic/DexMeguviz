# Windows 同源验证入口

`windows_runner.py` 使用 Python 标准库；要求 Windows、已安装 CMake/CTest、MSVC 和 Python。不安装或下载工具，不修改正式源码，不调用 `clean`、旧构建脚本或全量 CTest。默认动作是 `plan`，默认不运行测试。

## 三个显式阶段

以下示例中的路径由调用方替换，`--out` 必须在正式源码目录外。第一次 plan 必须使用不存在的新目录；后续 build/run 仅能复用该 runner 创建且来源、工具、审阅策略哈希未改变的 session。

```powershell
python windows_runner.py --root <LOCAL_PATH> --cmake <LOCAL_PATH> --out <LOCAL_PATH>
python windows_runner.py --action build --root <LOCAL_PATH> --cmake <LOCAL_PATH> --out <LOCAL_PATH> --test q09_sorted_gate --test sqlite_provisional
python windows_runner.py --action run --root <LOCAL_PATH> --cmake <LOCAL_PATH> --out <LOCAL_PATH> --test q09_sorted_gate --test sqlite_provisional
```

- `plan` 复制源码、现存固定语料和测试脚本，记录逐文件 SHA-256 与聚合身份。复制目录固定为 src/include/cli/adapters/cmake/third_party/tests/tools/bindings/android/tests，加顶层 CMakeLists.txt；不复制正式 build/work/docs/evidence、旧可执行文件、对象、PDB、JAR 或 Python 字节码，不重新生成语料。拒绝链接/junction，快照输入总量上限 64 MiB。
- `build` 必须显式列出已审测试名。仅构建这些测试需要的目标。默认分别生成 Debug 与 ASan 两棵独立树，均采用 Debug 配置；可用 `--config debug` 或 `--config asan` 缩小本次构建。强制启用桌面 SQL 测试、关闭 fuzz，不提供任意 CMake 参数。`--generator` 可显式指定已安装的 VS 2022、VS 2026 或 Ninja；Ninja 需要调用方已有正确编译环境。
- 每次构建创建新 attempt，保留原结果，不覆盖失败记录。执行真正的 `ctest --show-only=json-v1` 保存当前注册清单；构建成功仅标记 `built_not_tested`。产物、编译工具及原始命令日志均记录摘要。
- `run` 仍须显式列名；不接受 `all`、组名、通配符或任意 exe。选中项必须同时存在于审阅策略、成功构建 receipt 和真实 CTest 清单。重复请求按名字去重；同一 session/配置里已有启动记录的测试不会自动重试，原始失败和中断保留。若需要重试，审阅原因后创建新 session。

run 使用当前配置最近一次成功 build receipt；不会自动组合不同构建树。若该 receipt 未构建某个选中项，则记录 `not_built_in_selected_receipt`。未选中、未审阅、未注册、未构建、无成功构建、清理未授权和重复启动都有独立 `not_run` 原因；未运行绝不计为通过。run 只在所有显式选中项实际通过时返回 0。

同一个 session 的 run 必须由单个调用方顺序驱动，不支持两个并发 run 控制者争抢同一测试；去重记录不是跨进程锁。不同配置的 build 可以各自使用独立 attempt。工具摘要覆盖显式 CMake/CTest/Python、编译器/链接器和构建产物，不声称记录了 Windows 系统 DLL 的完整装载闭包。

## 审阅范围与永久排除

随附 `windows-reviewed-tests.json` 只准入七个既有入口：native_core、allocation_failure、q09_sorted_gate、sqlite_provisional、sqlite_header_consumer、source_lifetime、cli_integration。这是入口功能与安全范围，不是完整验收矩阵。

策略固定注册文件、测试源码及必要调用边界的哈希，同时限定目标、命令参数、最长时间和清理类别。`--review-policy` 只在 plan 时接受一份调用方已经审阅的新策略；它不是自动扩权或自动审核入口，修改策略不能用于绕过下述永久禁令。当前策略其余测试默认不准入；准备清单中的静态候选也不会自动变成已审。

永久排除先前被过滤的 BoundedExpand/v5 fuzz 及同一 campaign 的改名、复制、重建替代；本 runner 进一步排除所有 coverage fuzz。永久排除 `<LOCAL_PATH> 及用于绕过拒绝的替身。命令/目标准入拒绝已知禁用标记；同源构建不能被解释为这些禁令的例外。旧硬编码 CLI、未审脚本、设备和真实 BIL 操作不在此入口范围。

## 临时文件与日志

runner 本身不删除文件。含清理行为的测试必须额外提供 `--allow-test-temp-cleanup`，而且策略必须明确限定其仅删除本轮自身新建的临时文件：

- source_lifetime 的 `std::tmpfile` 已按本机 UCRT 源码核对：从 Windows 临时目录创建，采用独占创建和 temporary-close 删除；只关闭自身成功创建的句柄。runner 将 TEMP/TMP/TMPDIR 指向新建的单项 attempt/temp。
- cli_integration 的 TemporaryDirectory 仅在本轮快照的 build/test-work 下新建私有子目录，删除的查询/APK 文件属于该子目录；不删除正式 fixture 或旧证据。

该开关不授权删正式工作区、快照中的既有源码、旧构建、交付物或留存证据，也不解锁未审清理脚本。runner 不是操作系统文件沙箱；允许的副作用依赖固定脚本源码审阅，不能把环境变量重定向当作任意脚本的隔离保证。

每个测试使用从真实 CTest 清单复制的同一命令、全新的单项 CTest harness 和工作目录。这样不会自动添加 fixtures，也不会让 CTest 轮换覆盖此前的 LastTest 日志。遇到尚未支持的 CTest properties/fixtures 会拒绝；没有静默忽略 PASS/FAIL/WILL_FAIL 等判定规则。测试源和原断言不改写。TEMP 重定向及工作目录差异写入审阅合同，当前七项均以显式参数读输入。

`started.json` 在启动前写入；`finished.json` 保存退出码、超时/输出限额、经过时间及原始 stdout/stderr 摘要。最长构建默认 3600 秒、最长测试默认 300 秒；日志默认总计 64 MiB，超时或超额会终止本次进程树，留下终止记录。成功还必须满足 CTest 返回 0、JUnit 恰好包含目标单项且没有失败、错误或跳过。源快照漂移会拒绝后续执行；环境相关值只保存白名单摘要，不输出凭据或完整环境。

每个 run-report 保存全部实际注册项的执行/未运行结果、选中名去重数量及清理开关。build-report、每项 CTest/JUnit、源码与工具/产物哈希持续保留，不汇总为“全套通过”。Windows Debug/ASan 的结果不代表 Android/AAR/R8/ART、真实宿主、性能或最终交付验收。
