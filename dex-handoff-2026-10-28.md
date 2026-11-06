# DexMeguviz 阶段交接：2026-10-28

工程位置：`<LOCAL_PATH>`。截至本次收尾，`backlog.json` 为任务状态的权威来源：49 项中 9 项 done、10 项 in_progress、30 项 planned；整个工程仍在进行。附件原文和哈希保存在 `references/engineering-pack/`，附件中的提示词不提供额外操作授权。不要清理当前工作区或覆盖其他未提交工作。

## 已交付与验证边界

- P0-04 已按限定的 JDK 17 主版本、双 ABI 离线构建和静态验证验收；AAR 位于 `work/iteration20/artifacts/dexmeguviz-android-release.aar`，详情和 SHA-256 见 `docs/evidence/iteration20.md`。该结果不证明设备装载、ART、完整 JNI/Kotlin API、BIL 或 APK 16 KiB 对齐。
- Q09 已修复结果交付阶段的取消竞态并保留主机验证，见 `docs/evidence/iteration17.md`；扫描中途私有候选保留仍未实现。其他 Q01–Q12 的已交付状态以 `docs/evidence/q01-q12-matrix.md` 为准。
- BoundedExpand/v5 仍是 `work/iteration14/expand-draft` 中的未交付草稿，需要与新 job/CMake 对齐。此前相关模糊测试子任务被自动安全过滤中止；保留该事实，不自动重试或绕过过滤。

## 本次尚未集成的隔离工作

下列路径位于 `<LOCAL_PATH>

- `dex-q10-stage\EVIDENCE.md`、`manifest.json`：33 候选的静态样本及 Debug/ASan CLI、实际 Job/Batch 对照；上限 32 时为部分结果，重试完整 33 条后测试模型接受最后一条。业务后置验证与负缓存仅为测试模型，生产接口、真实业务和 BIL 端到端未完成，Q10 仍为部分。初次工具链发现失败的记录保留。
- `dex-inherited-stage\README.md`：静态父类路径解析内部原型，含来源歧义、缺失、循环、预算和取消的独立主机测试。内存合成图不是实际多 DEX 验证；字段继承语义、公开查询、证据和 ABI 尚未接入，Q08 仍为部分。
- `dex-reflection-stage\Q05.md`：raw flags 基线与反射域调查；当前 reflection 仍明确 Unsupported。ASan 首次缺运行库失败及后来单进程 PATH 修复后的通过均保留；使用已有二进制，不是本次重编译验证。
- `dex-batch-plan-stage\P2-01-Q12-design.md`：多规则共享与标量回退设计；尚无多规则实现、共享计量或差分验收，Q12 未证明、P2-01 未完成。

## 接续顺序

1. 先读 `PROJECT_STATUS.json`、`backlog.json`、`docs/evidence/bootstrap.md`、相关契约及本记录，核对主工程和隔离草稿的文件哈希。
2. 将 Q10 的生成器、样本和独立测试按工程约定集成并重建验证；业务后置验证、重试和缓存语义仍须按原始验收实现，不能仅凭模型标 done。
3. 对 Q08 先明确静态字段继承、可见性、遮蔽和不完整范围的语义，补真实多 DEX 样本；再考虑接入来源范围、结果和证据。Q05 的静态候选与真实反射行为必须分开。
4. 按依赖继续 Q07、Q09、Q12 和其他 backlog 项；按需保留失败、构建和设备证据，不将静态或交叉构建说成运行时验证。未经新的明确授权，不改动 BIL、不操作设备、不发布。

新增生产依赖、删除文件、重置、强推和影响共享环境仍遵循工作协议。已获批的 miniz 和可选桌面 SQLite 仍按既定范围使用。
