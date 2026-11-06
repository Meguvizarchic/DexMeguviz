# 启动阶段反例与修复

日期：2026-10-26。

## 损坏 class_data 首项被误作完整空关系

交叉审查构造反例：在448字节minimal.dex中，把class_def的class_data_off从322改为330，330..333写零，而map仍声明首项322。原实现只检查section内范围和引用条目总数，导致内部四个零被读成空class_data，可能给出错误Complete/NoMatch。

修复为校验实际引用的byte-aligned class_data/string_data条目：首项必须等于map起点，相邻条目连续，数量一致。独立Python oracle同样从原始字节校验。两个恶意语料已登记并纳入Debug/ASan行为回归。此修复未补全所有variable item、指令或CFG验证。

## CLI输出断管被误报成功

复现为启动inspect后立即关闭stdout接收端；原代码未检查cout，退出0。修复为集中write/flush并检查状态，失败返回4且仅写stderr，不再输出第二份JSON。Windows行为回归已纳入CLI集成；POSIX SIGPIPE分支未在本轮实际运行。

## MSVC Debug分配故障注入触发terminate

完整Debug下向第1个分配点注入失败，会在Source的vector默认构造中terminate。已读本地MSVC14.51的vector:672–673与xmemory:1231–1235：noexcept构造调用Debug iterator proxy分配。此类运行库调试设施不受C ABI异常捕获保护。

保留普通Debug目标的迭代器检查；新建专用fault测试可执行文件，所有被测源码与测试一起编译，并只在该目标定义_ITERATOR_DEBUG_LEVEL=0。160个分配注入位置实际执行；普通Debug与ASan仍独立执行。未通过调大超时或吞异常使测试变绿。

首轮及诊断失败日志保留在docs/evidence/host-debug的旧记录中，最终通过记录由latest.json指向。缺少取消检查点、完整资源账本、release配置和其他host平台验证仍明确保留。
