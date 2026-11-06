# Android 显式持久方法事实缓存 v1

Android library 默认不包含此桥或持久缓存实现。仅显式以 `-Pdmg.persistent=true` 构建时，Gradle 把 `src/persistent/java`、附加 R8 keep 规则和对应 CMake 开关加入本次AAR；没有新增运行时生产依赖。该参数只改变构建，不能自动修改宿主、安装设备或启用缓存。值只接受 true/false。纯C/C++扩展仍由单独的桌面开关管理；这不是对旧Android默认接口的隐式改变。

宿主持已有的 `NativeEngine.Snapshot` 或 `SourceSetSnapshot`，调用 `PersistentCacheBridge.open(snapshot, directory, limits)`，目录应是调用方自己控制的应用私有目录，并信任所有可写入者。open可创建目录；不验证APK签名、ClassLoader或写者。`Limits` 的零值表示已有默认，非零必须满足单片≤256 MiB、目录≤4 GiB、条目≤65536、每列≤1048576和目录≥单片；还可设置更小的预算。目录、文件系统及IO临时开销不计入Engine的managed-bytes；不能把这些额度理解为RSS上限。默认目录容量256 MiB、每片64 MiB、2048项，每个完整片可能保留pending和硬链接两个目录名；没有自动删除。

例如，已有 `NativeEngine.SourceSetSnapshot snapshot` 和只由本应用控制的 `File cacheDir` 时：

```java
try (PersistentCacheBridge cache = PersistentCacheBridge.open(snapshot, cacheDir)) {
    NativeEngine.QueryResult result = cache.queryMethods(queryJson);
    long[] counters = cache.statistics();
    // 按result的coverage和decision判断当前静态范围，不从缓存命中推断业务接受。
}
```

持久会话只接受已公开的 **同步 direct method-v1** `queryMethods(byte[])`：与原同名快照方法使用相同query形状、无显式scope、结果上限4096、工作上限100000000、结果复制和incomplete scope合同。执行基于同一已打开snapshot，缓存仅物理方法facts，结果/唯一性/负判定、绑定或业务结论不落入缓存；旧方法和Job不自动使用此缓存。`statistics()` 返回7个复制的非负long，顺序为hits、misses、rebuilds、rejected、published、writeFailures、bytesRead，不代表速度或全程IO。

每会话引用原JNI snapshot owner，内部C cache绑定其Engine；会话close和调用按Java实例同步，底层注册表保活正在进行的调用，最多16个活跃/正在打开的缓存会话。调用方应关闭cache会话和snapshot；关闭snapshot后会话的后续查询返回CLOSED，已通过native准入的查询允许完成。会话关闭后不能再次使用。不要依靠GC自动关闭；调用期间不得修改query数组。没有异步持久缓存Job、deadline/cancel或隐式跨snapshot共享句柄。不同会话如选择同一可信目录，使用POSIX非阻塞发布锁及唯一pending/hard-link协议；同UID恶意替换不在此安全模型内。

缓存读取、损坏或发布失败沿现有扩展合同回退真实collector；如果目录本身无法创建、不可访问或不安全，open失败并由宿主决定是否使用原snapshot查询。硬链接或锁在特定文件系统不可用时不把缓存失败当作空匹配。Android具体文件系统和ART/设备运行仍需实际验证，NDK编译或主机JVM检查不能证明其存在或性能收益。
