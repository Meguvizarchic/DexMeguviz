# 离线候选包

生成配置提供 `schema_version:1`、`namespace:"cli-v1"`、`model_version`、`scope_complete`、有序 `inputs` 和 `rules`。每条输入包含 `path`，可指定 `format:"raw"|"apk"`、`role`、`slot`。每条规则必须包含 `id`、`version`、`profile`、完整 QueryIR `query`、角色到候选索引数组的 `roles`。

```powershell
python tools/precompute/package.py build --config config.json --cli PATH_TO_TRUSTED_CLI --output result.dmgpre --expected-output expected.json --workdir NEW_RUN_DIRECTORY
python tools/precompute/package.py consume --package result.dmgpre --expected expected.json --current current-sources.json
```

所有输出路径必须未占用；不会覆盖或删除。调用方应独立保存/审核 `expected.json`，不能将包自带声明当作期望。消费配置需提供当前 namespace/model/scope 和有序输入；不读取包中的文件路径来打开来源。

Python 库接口：`build_package(config, cli, output, root, workdir)` 返回期望清单；`load_candidates(path, expected, current, root)` 返回局部校验后的候选报告。导入 `tools.precompute` 即可使用，均为 opt-in。来源/版本/预算错误通过 `PackageError.status` 区分；局部校验错误继承 `LocalError`，需要按未命中/拒绝处理，不能降级为成功空集。

结果只供调用方继续绑定和业务验真。格式、支持范围和未实现部分见 `docs/contracts/precompute-v1.md`。
