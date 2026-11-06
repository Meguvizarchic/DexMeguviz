# ADR：归档后端（工程计划保留的交付路径）

2026-10-26。使用获用户明确批准的miniz3.1.2固定发行包，commit和本地校验见third_party/miniz/upstream-lock.json；保留MIT许可，不改上游源码。只编译读取/inflate能力，关闭stdio、压缩与归档写入，通过实例级allocator callbacks接PMR账本。

选择理由为单一可移植C组件、无额外生产codec、每archive可独立计账、流式提取可插入取消检查。未采用libzip+zlib的双组件路线；当前选择不构成速度或手机内存收益承诺。

先限制目录/名称/entry/输出，按完整名称判重，不信stat的固定长度展示缓冲；本地/中央头与descriptor独立检查。最终iterator free完成CRC与实际长度验证后才返回拥有型条目，取消和预算不能发布完整结果。ZIP64、长名称、zipalign短零填充、损坏/预算/取消都有生成式行为测试。

原始APK与DEX强摘要、ZIP CRC和DEX结构验证分别报告。完整SourceSet保持有序input/occurrence，资源-only包不丢身份；压缩副本在成功解压后释放。实现及边界见src/source/archive与docs/contracts/source-set-v1.md。
