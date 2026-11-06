# 不执行查询的计划说明

`dexmeguviz explain --query QUERY.json [--json] [--budget-mib N]`只编译查询，不接受DEX输入或source/scope运行选项，不创建snapshot、扫描DEX或决定来源完整性。QueryID/能力/按需列/投影/意图/限额、关系树、角色、分支次序、展开界限和排序可观察；runtime为null。执行模型以标量参考语义为基准，索引/缓存选择依赖运行数据与显式选项，不在无来源时伪造命中或成本。

新增C `dmg_query_get_explain_*_v1`视图。operator访问参数是枚举序号，返回node_id/child是编译计划稳定ID；两者不能混用。scope getter的operator_index=UINT32_MAX读取全局scope，其余读取对应算子scope。label/role/slot字符串借用Query，需保持Query有效；错误size/索引不写out。旧C结构和QueryID语义不改。字段按op解释，非对应算子的expand/join/group字段不作为已启用能力。

本轮只做Release构建、独立C无snapshot计划读取以及一条CLI展开计划说明。完整ABI错误参数/旧域/资源/跨平台专项待统一。
