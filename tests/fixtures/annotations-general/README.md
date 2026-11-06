# 通用注解自建夹具

`Annotated.java` 是项目自建的类、字段、方法、参数注解和数组/嵌套/字符串/类型值；`classes.dex` 使用已安装JDK17 javac `--release 8` 和Android Build Tools 37.0.0 D8 `--min-api 27 --no-desugaring` 生成。`expected.json` 的槽位与类型经独立dexdump检查；不含真实应用材料或ART运行证据。项目夹具分发许可待所有者决定。

`python -B generate.py --javac <javac> --java <java> --d8-jar <d8.jar> --out <新目录>` 在新目录生成并保留中间文件，不删除；不同工具版本可能导致不同字节，正式对照应核验现存DEX SHA。
