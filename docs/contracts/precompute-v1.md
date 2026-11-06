# 离线预解算候选包 v1

`tools/precompute/package.py` 提供标准库 Python 生成/消费接口。生成端调用调用方明确指定的本地 CLI，执行规则查询后写包及独立期望清单；消费端不执行 CLI 或包内代码，也不把包记录当作运行时绑定。

生成子进程的 stdout/stderr 在读取过程中分别限制为 16 MiB/1 MiB，超限立即终止该生成进程，保留已捕获前缀和 command/error 状态；不等完整输出进入内存后才检查。使用点的声明 relation 必须与实际 opcode 引用类别相符，caller ordinal/reference/descriptor 要与当前方法一致；展开 hop 的 caller/resolved 必须为 method_defs，不能借其他实体域的相同整数索引冒充方法。

包头为 little-endian `<8sIIQ32s>`：magic `DMGPRE01`、版本 1、头长度 56、JSON payload 长度、payload SHA-256。单个规范 ASCII JSON 段最大 16 MiB；不接受尾部字节、重复键、非整数数值、超过深度/项数上限的结构。输出使用排他创建和 fsync，不覆盖现存文件；写入中或中断后未完整的文件在读取时按长度/摘要拒绝。没有自动删除、隐式替换或缓存清理。未知格式、验证器或 profile 走 Unsupported，摘要、版本、当前来源和局部证据不一致分别返回明确错误。

payload 保存 model/version、精确有序来源、生成 CLI 摘要、局部验证器/指令宽度表版本、每条规则的 id/version/profile、完整查询及 QueryID、角色到候选的映射、原始结果和局部证书。规则/profile/摘要的自报值不是信任来源：消费必须由调用方提供独立保存的期望清单，包括整个包摘要、查询身份/查询内容摘要、规则版本、角色映射摘要和来源/model版本，并与当前来源实读结果比较。把包和期望清单一起从不可信发布者下载不会自动建立信任；本实现没有签名/发行认证策略。

来源为有序 raw DEX/APK 输入，保留 slot、role、格式、字节长度、强摘要和每个 canonical classes*.dex 的实际 occurrence 顺序、archive entry/central index。资源 APK 可显式为空，重复 occurrence 保留，新增/移除/重排/重包/模型改变均失效。目前 namespace 固定 `cli-v1`；生成 slot 与当前 CLI 的输入路径域一致，消费可用新物理路径，但调用方须显式携带原来的 logical slot。source 输入最多 64、单 DEX 64 MiB、总输入和总展开 DEX 各 512 MiB；ZIP 不解压到文件，拒绝重复条目、加密/未知压缩和非规范 root DEX 名称。

内置局部校验覆盖七类实体的表记录/descriptor、选定类中定义所属与属性、普通字符串/方法/字段/类型使用点、已支持的普通指令见证和展开 hop 的调用/解析符号。它读取相关表条目、class-data count 前缀及选定方法体，不重新执行完整定位查询。复用现有独立证据工具的有界格式、MUTF/ULEB和本地 opcode 宽度资料，不调用 native reader。允许容器 profile 为 v1/v2/v3/v4/v5/v16/v21/v22，但各条实际证据仍需满足局部校验形状；特殊 invoke、继承/反射/数字/字符串池不存在证明等未实现形状明确拒绝。原始字节身份和局部事件可核验，不等于完整 DEX verifier。

返回 `CandidatesLocallyVerified`：保留 descriptor、角色链接和原始证据，`producer_claim` 单独携带覆盖/决策，`query_decision_verified=false`、`runtime_binding=NotPerformed`。局部证书不重证全域 Unique、absence、否定完整性、关系总数或业务接受；这些结论不能直接写 FOUND/MISSING 或替换 BIL 后验。运行时仍需当前 loader/来源重核、绑定和业务验真。空结果也没有因此被证明为 MISSING。

计时分别报告包读取/校验、来源读取/哈希、局部验证和总时间；未运行的绑定不伪造耗时。`full_locator_scans=0` 仅指消费没有重跑规则定位，仍有必要的来源 I/O、解压、哈希、表访问与局部方法字节读取。当前不与 P4 物理事实持久缓存共享 codec，不声称跨进程缓存命中或性能收益。

自建 raw DEX 及多来源方法/类/使用点/展开结果已有生成→消费连通。BIL 桥现支持显式 resource-split：纯资源APK仍被计入有序输入和强身份；标为resource-split的APK若包含DEX，仍枚举并验证其DEX，不能由role推断无代码。base+code split+空资源和含匹配DEX的resource split已做自建主机包→JVM/JNI桥连通；独立expected、显式producer完整枚举政策、当前绑定与attestor均未放宽。其他APK/局部实体及版本/损坏/截断/资源边界、崩溃/并发、真实BIL/device与性能仍须专项。P4-03仍进行中，发行认证与运行时验收尚未完成。

## Producer 声明字段与可信桥

消费器的 `producer_claim` 仅投影包中原始执行状态、覆盖、决策、终止原因、访问/总方法数、来源范围、顶层 Unknown 是否存在及其值、`query_profile.unknown_rows`、`query_scope` 的完整性/显式位/来源索引，以及可选 `profile_v1` 的producer、phase、QueryID和运行scope/Unknown。缺失或错误形状保留为 null，不默认零；Python 与 JVM 使用相同字段名。该投影不是认证或完整性证明，`query_decision_verified` 等标志保持 false。

BIL 的单查询可信快路径还须按 `integrations/bil/docs/precomputed-bridge-v1.md` 对这些声明做严格一致性检查，缺失/冲突直接回退原生；历史v1 CLI不产生顶层 Unknown，使用实际的 `query_profile.unknown_rows`，且无 `profile_v1` 的历史包仍可经过其余完整门控。存在该外层时其内容必须一致。该检查不扩展v15、特殊invoke、分支角色或真实运行时认证范围。
