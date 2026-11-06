# D8 code_item 末尾 1/3 字节填充

`d8-odd-1.dex` 与 `d8-odd-3.dex` 分别由项目自建 `ManyOdd.java` 的 `finally` 与多 catch/finally 变体通过 JDK 17、Android build-tools 37.0.0 D8 和 min-api 27 生成；源码随证据保留。两文件均为 DEX 038，SHA-256 分别为 `2e5197d47ad51bb7d488285c0a409af0f2f6bd3a03c8f0104ac9a041e58ca75a` 和 `a2ccdaba46de49c3c734bc2b9fd9e03bbcb8b344869c9746e758724c49300232`。

独立解析包含 try/handler 的 code_item，末项分别在343和397结束；下一 string_data 分别从344和400开始，中间的1和3字节全部为零。`code_padding_odd_tests.cpp` 对原件和逐字节非零变异进行 reader 增量测试；变异直接调用 reader，不验证变异后的 DEX 头校验和。该测试当前需作为独立目标编译，未注册在项目 CTest。
