# 接续同源构建的验证

`tools/verify_built_run.py` 只消费 `run_same_source.py --mode build` 的完整成功输出。调用方独立提供该构建 `plan.json` 的SHA-256，并提供全新、与构建目录互不包含的out。默认仍为plan-only。

```powershell
python -B bindings/android/tools/verify_built_run.py `
  --built-run '<完整构建目录>' --expected-plan-sha256 '<已审构建plan摘要>' `
  --out <LOCAL_PATH> --mode verify
```

接续前检查 `built_not_tested` 完整状态、四个构建步骤的顺序/argv/退出状态/日志摘要、source manifest、源码原始文件及隔离快照、已选工具、实际配置的host compiler、Gradle解析产物、五项AAR/classes/JNI/POM/module构件、runtime报告和继承Java环境选项摘要。另固定该新构建实际产出的writer测试exe及接续工具自身摘要，在使用前后复核。不会接纳任意历史JNI、CLI或只提供一个DLL的“成功”声明。

接续只重定向原计划中的验证输出：host class目录、AAR audit、binder/member、R8、jni-summary与日志。源码、fixture、AAR/classes.jar和JNI都保持为已核验的构建路径，原构建目录证据不写入或覆盖。R8所需passed jni-summary只有前面的主机步骤真实通过后才写入新out。任一步失败立即停止，未执行项逐项保留，不把建成当验证通过。所有输出保留，不自动重试或删除。

这不是从失败/部分构建恢复，也不是发布、设备或fuzz入口；沿用原计划有限固定样本的范围。环境选项只记录存在性和摘要，日志启动banner遮盖规则与构建runner一致。接续会再次校验原构建输入及证据未变；操作系统/JVM自身全文件行为并非文件系统沙箱承诺。

如已审计划误接了现有测试的fixture，可显式提供 `--fixture-overrides <JSON>` 和独立 `--fixture-overrides-sha256 <SHA>`。JSON必须绑定原build plan摘要；每项只能把该原消费者原fixture参数，替换成同一已冻结snapshot中的既有fixture，并逐项匹配原source-manifest的SHA。它不能修改Java可执行文件、main、测试源码/断言、编译参数或其他验证步骤，不能添加外部路径；新计划完整保留变更及理由。原构建/源码/计划和旧失败记录仍不修改，不据此将未跑或失败测试标为通过。

本轮实际接续先保留一次错误fixture映射失败，再用经复核、摘要绑定的单项fixture覆盖完成17步。没有重新构建AAR/core，没有改原测试断言，原构建目录及收据经前后摘要核对保持不变。具体构件和执行范围见交付验证清单，不扩成设备或全profile验收。
