# D8 code_item 尾部零填充夹具

`d8-minimal.dex` 是项目自建一静态方法 Java 源使用 JDK 17 和 Android build-tools 37.0.0 D8（min-api 27）生成，SHA-256 `49cfdb3f69c389a00f93b6e5834173da5156027b4bf61ab1e9bc5265eb567a1f`。其第二个 code_item 结束于258，后接两个零字节，下一 string_data 从260开始。生成脚本为 `../../generators/d8_code_padding_fixture.py`。

它只用于 reader 静态元数据与结构测试，未证明设备 ART 行为；测试中更改字节的反例直接调用原始 reader，不验证 DEX 头校验和。
