# 自建类注解字符串夹具

两份 project-authored Java/D8 输入中，`Collision` 的 VALUE_STRING 均引用局部 string_id 22，但内容分别为 `aaaa` 和 `bbbb`；另有空串、雪、代理对、孤立代理及内嵌 NUL。`expected.json` 固定源码与 DEX 摘要；字节语义仅用于静态验证，不代表 ART、真实 APK 或性能。

使用已安装的 JDK 17 与 Android build-tools 37.0.0 的 d8.jar，运行 `python -B generate.py --jdk <JDK_HOME> --d8-jar <d8.jar> --out <新目录>`。生成器检查两个 DEX 的固定摘要并保留命令日志，不覆盖或清理已有目录。
