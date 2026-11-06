# 纯 JVM 离线候选消费桥

`io.github.jichuo1.dexmeguviz.precompute.PrecomputedCandidates` 消费 `tools/precompute` 的 DMGPRE01/v1 包。实现不加载 DexMeguviz native、不运行 producer CLI、包内代码或反射绑定；只使用 Java 标准库的文件、ZIP、SHA-256 和有界解析。Kotlin 可直接调用该 Java API，不新增运行时依赖。

## 独立输入与输出

```java
PrecomputedCandidates.Result result = PrecomputedCandidates.consume(
    packageBytes, independentlyTrustedExpectedBytes,
    currentModelVersion, declaredCompleteStaticFileScope,
    orderedCurrentSources, limits);
```

`SourceInput(file, logicalSlot, role[, format])` 由调用方独立提供，不能从包里的路径自动打开来源。slot/role 保留原逻辑身份，物理文件可以迁移；format 为 raw/apk，省略时按文件魔数检测。当前 namespace 固定 cli-v1。模型版本、来源次序、重复出现、资源-only APK、每个 DEX 的条目名/中央目录序号/摘要均须与独立 expected 相符。外部 expected 必须由调用方可信保存或审核；把它和包一起从不可信发布者获取不会建立认证。

Result 包含 typed Source、按 ruleId 可取的 Rule、来源身份和重新计算的 SnapshotID。Source 包含 slot/role、输入与DEX摘要、entry/centralIndex、ContentId/LogicalDexId/OccurrenceId；相同DEX字节在不同来源仍是不同 occurrence。Candidate 提供当前字节重建的 `verifiedPrimary` 和 typed identity/owner/name/prototype/typeDescriptor 等值，以及完整、不可修改的 `raw`。use候选的 callerOrdinal/callerMethodRef/dexPc/targetIndex 与实体 localIndex/referenceIndex 分开，避免把局部域混在一起。Rule 保留 roles、frontiers、局部证书和原始 producerClaim。

**Result/Rule 的 queryDecisionVerified、completeEnumerationVerified 均固定false；origin固定UNVERIFIED，runtimeBinding固定NotPerformed，packageAuthenticated固定false。** `CandidatesLocallyVerified` 只表示所返回局部实体/事件与当前字节及受信期望一致。metadata witness 没有因此证明整个 where；局部 hop 没有证明全域候选数或解析唯一性；空候选不证明全局不存在。不得直接生成 FOUND/MISSING 或持久化业务成功。要跳过完整定位，必须另有独立、明确的可信 producer/完整枚举政策，随后仍须做当前 loader 绑定、attestor 与业务验真。

## 格式和本地核对

先复制包与expected输入，检查56字节小端头、magic/版本、精确长度、payload SHA-256及独立整包摘要。JSON 拒绝重复键、尾随内容、非整数数字和过深/过大的树，保留JSON escape中的UTF-16单元。canonical编码与Python ensure_ascii/sort_keys规则对应，包括非BMP键的码点顺序；不用无预算第三方JSON库。

本地协议只接受 `dex-local-bytes-v1`，指令宽度表是源码中的只读固定数据，摘要为 `7eaa06d9d7566adf82e23dea293aa9c0b41f7838fb698a1a8c19f756f78222c7`，不采用包提供的宽度数据。规则版本、profile、QueryID、查询及role映射摘要与独立期望核对。当前支持集合与桌面v1一致：v1/v2/v3/v4/v5/v16/v21/v22容器profile；实际见证仍限已实现的七类实体、普通string/method/field/type使用点、no-body/instruction-scope及普通展开hop。特殊invoke和高级继承/反射/数值等未支持见证明确拒绝，不能只因容器profile在名单里就跳过见证。

本地DEX读取移植自项目的 `tools/precompute/local_dex.py`，不调用native reader。核对本地表/声明位置、完整符号、方法体范围、PC边界、使用点族、caller/目标和hop的方法域；每张既有证书都要重建且逐值匹配，缺项或多项均拒绝。源码还按 source-set-v1 的UTF-8长度帧独立计算content/logical/occurrence/snapshot身份，候选中的身份字符串不能只靠producer自报。它仍不是完整DEX/ART verifier、控制流或查询完整性证明。

## I/O、限额和失败

输入/APK用流式摘要；ZIP在创建ZipFile前有有界EOCD/ZIP64和中央目录条目预检，选中DEX校验解压长度/CRC。条目不解压到文件。当前DEX按需复制到JVM并核对摘要，使用期间不可被调用方更改；结束前重新读取输入摘要，仍不声称排除同权限恶意ABA替换。Java/Android ZipFile自身不支持的合法边缘ZIP布局也可能被明确拒绝。

包及expected各16 MiB；64个输入、每输入256 MiB、总输入/展开DEX各512 MiB、每DEX64 MiB、1024个DEX occurrence、ZIP最多100000条目、128条规则、每规则4096候选。JSON每文档200000项/深度64/单字符串1048576码点；累计文本8 Mi UTF-16单元，证据递归深度48，逐规则单DEX读取工作2000000。Limits默认累计物化DEX 128 MiB、局部工作1e8、截止30秒，可降低；检查点也读取调用方可选cancel supplier。限额不是JVM堆/RSS或硬实时时限；普通OutOfMemoryError不伪装成成功空集。所有失败均不返回部分Result。

调用方必须在consume期间保持输入列表、文件内容和取消回调的约定稳定；回调不应抛异常或重入。Sources没有从包获取执行权限。数据复制、完整I/O/哈希/解压与局部读取都会发生，不能称零I/O命中；方法体之外的全规则定位没有执行。

## 当前验证范围

Java17编译及一份新桌面包→JVM连通通过：同一APK中5个DEX、资源-only APK、重复内容raw来源、Unicode路径和重定位physical raw路径；4条method/class/use/expand规则的完整候选与role数据可读取，重复内容LogicalDexId相同而OccurrenceId不同，验证旗标仍为false。首次上下文三元表达式导致null拆箱，修为显式分支，原代码/失败日志保留。没有执行完整坏包/ZIP/UTF/限额/取消矩阵、Android AAR/R8/设备或真实BIL命中验证。P4-03仍在进行中，当前桥不自动写L0或跳过绑定。

## minSdk 27 API边界

源码使用有界InputStream循环、File、旧版Collections/Arrays和标准MessageDigest/ZipFile；未使用InputStream.readAllBytes、Path.of、List.of或HexFormat。依据本机官方SDK api-versions.xml，ZipFile(File,Charset)、List.sort、BooleanSupplier为API24，Objects.equals/Integer.compare为API19。最初BigInteger.longValueExact（API31）已改为compareTo校验long边界再longValue（API1）。这是静态API核对，不等于API27设备运行；桌面测试中的Files.readAllBytes不进入库。

根合入边界补充：来源数量在列表复制前检查；选中DEX数量在加入排序集合前检查；中央目录最多16MiB、名称原始字节合计最多8MiB，沿用项目ZIP预检尺度。classesN序号限定uint32且排序计工作，避免为超长数字名构造任意精度整数。该补充不改变局部/producer验证分层，超限明确失败；不是JVM/RSS总量保证。
