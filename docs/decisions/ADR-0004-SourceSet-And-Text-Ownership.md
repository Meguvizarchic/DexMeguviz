# ADR 0004 多来源身份与元数据文本所有权

日期：2026-10-26；状态：本地实现与相关验证推进。

多来源通过不可变Dataset承载有序InputRecord和逻辑Source。Source保留物理DEX字节/Facts，候选携带source_index，跨来源不合并相同descriptor。资源-only APK进入Snapshot身份。来源缺口与已完成遍历分开建模，不允许Unique/NoMatch假证明。

Occurrence升级v2，对raw-input/archive-entry、原slot、role、entry分别frame。初版拼接effective slot有构造性身份碰撞，已用C API回归和独立Python身份重算验证修复。

真实9.17首次因合法zipalign短零填充被拒绝。AOSP ZipEntry::addPadding证实只向LFH extra追加零字节。现在仅容许本地extra最后不足4字节的全零尾部；完整未知TLV继续按长度跳过，非零截断、中央目录短尾和缺失必需ZIP64字段仍拒绝。依据：https://android.googlesource.com/platform/build/+/refs/tags/android-9.0.0_r1/tools/zipalign/ZipEntry.cpp

真实9.17在1GiB managed预算下随后触限。先释放已完成解压的压缩副本，再消除每个Method重复持有的owner/name/prototype文本，改用同Facts内稳定目录视图；结果物化时才复制。Facts禁止copy，move assignment要求同一PMR resource，防止跨allocator移动使视图悬空。此变更有PMR禁用默认资源、移动、错误拒绝、Result/Batch保活与线程只读测试。

优化后同一1GiB预算读取9.17的35 DEX、9.14的33 DEX成功，全部摘要和声明计数经Python独立重读一致。这是host Debug静态兼容性与预算行为证据，不是正式性能提升、RSS改善或Android生产替换结论。
