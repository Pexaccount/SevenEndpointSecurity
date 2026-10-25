# SevenEndpointSecurity
## 注意事项

- 详细阅读以下内容来获得稳定且安全的使用体验
- "在控制台 > 设置"中开启DefenseMode来关闭进程防护，获得最低误报且最稳定的模式（适合日用）
- 无UI Endpoint，EDR & EPP架构。
- 移除了ETW遥测，因为Worker同时处理30万条ETW事件，崩溃了。
- ETW处理还是需要Rust、C++、C这样的语言，Python踩坑了，因为成功接上ETW就花了我一周。
- 软件拦截并非删除，防止资料被误删。
- 规则打磨了很久，主动防御误报很低。
- 引擎误报问题会一点点减少，请谅解；因为是v0.0.3，也打磨了很多个月。
- 若您的计算机可正常加载驱动（发行版本），那么 [Kvc](https://github.com/wesmar/kvc) 驱动可以成功加载，程序主进程可以获得 PPL（稳定）。
- 托盘右键可以打开控制台来查看详细信息
- 控制台中可打开详细被拦截的威胁的操作链（拓补链）可大致还原程序行为
- 若您需要让您的AI工具或您来修改代码，可以参考文档[Docs](https://github.com/Pexaccount/SevenEndpointSecurity/tree/main/docs)

---

## 架构说明

由Python编写，用户态杀毒软件，未使用不稳定的驱动内核。
本杀毒软件的拦截构建分为 **EDR** 和 **Endpoint**，虽然不能和 PYAS、XIGUASecurity 对标。

- 动态分析和静态拦截
- 加入ABD感染保护
- 加入Behavior EDR
- 单 EDR 架构为初版时使用  
  （此开源版本为最新上传的版本，但“最新上传不等于最新”；旧版已被遗弃、删除）
- 由于代码维护性太差（屎山），可以用拆分器把模块拆开查看

---

## SevenEngine V2 Flash Preview

- 误报降低
- 新增了两个自制杀毒软件的反病毒引擎（Xdows & Tanka2）
要是有白文件，也可以发送至 `pextechnology@qq.com`

---

## 反馈与联系

若您遇到问题，请向 `pextechnology@qq.com` 汇报，也可以发送误报文件。

其中的扫描引擎和数据若有不足也请汇报；或者有更好的选择，可以告诉我们！

- QQ 群聊：`777353898`
- BiliBili：`Karlmayer`

——感谢使用
