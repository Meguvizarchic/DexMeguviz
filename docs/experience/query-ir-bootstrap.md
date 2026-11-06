# QueryIR 初轮经验

1. 语义测试失败先回到独立fixture原文：external是引用身份说明，实际方法名为sink；修正期望后所有语义检查通过。
2. 相同canonical QueryID必须有同义的证据node_id。仅对hash排序而保留原节点编号会造成缓存/解释歧义；现在按canonical树分配稳定编号并统一纯逻辑子节点顺序。
3. JSON临时树、持久Plan、执行scratch和结果分别计账；Result/Batch需持有Plan，不能在Job结束后丢失QueryID/证据解释。
4. 方法按需事实先统一需求闭包，再进行多个谓词判断；真实静态例只解码相关2029方法而不是全APK方法体。此计数不代表已证明C/B净性能收益。
