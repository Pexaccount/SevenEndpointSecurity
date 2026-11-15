# SevenEndpointSecurity
## 注意事项

- 详细阅读以下内容来获得稳定且安全的使用体验
- **在控制台 > 设置"中开启DefenseMode来关闭进程防护，获得最低误报且最稳定的模式（适合日用）**
- 无UI Endpoint，EDR & EPP架构。
- ETW重新在C语言的SevenAgent启用。
- 软件拦截并非删除，防止资料被误删。
- 规则打磨了很久，主动防御误报很低。
- 引擎误报问题会一点点减少，请谅解；因为是v0.0.3，也打磨了很多个月。
- 若您的计算机可正常加载驱动（发行版本），那么 [Kvc](https://github.com/wesmar/kvc) 驱动可以成功加载，程序主进程可以获得 PPL（稳定）。
- 托盘右键可以打开控制台来查看详细信息
- 控制台中可打开详细被拦截的威胁的操作链（拓补链）可大致还原程序行为
- 若您需要让您的AI工具或您来修改代码，可以参考文档[Docs](https://github.com/Pexaccount/SevenEndpointSecurity/tree/main/docs)
- [SevenEngine云鉴定](https://sevenengine-cloud.onrender.com/)

---

## 架构说明

由Python和C语言编写，用户态杀毒软件，未使用不稳定的驱动内核。
本杀毒软件的拦截构建分为 **EDR** 和 **Endpoint**。

- 动态分析和静态拦截
- 加入ABD感染保护
- 加入Behavior EDR
- 加入了C语言的SevenAgent行为保护和更多规则，ETW事件流和WMI实时回调
  （此开源版本为最新上传的版本，但“最新上传不等于最新”；旧版已被遗弃、删除）
- 由于代码维护性太差（屎山），可以用拆分器把模块拆开查看

---

## SevenEngine V3

- 重构为940维的LightGBM引擎
- 新增了两个自制杀毒软件的反病毒引擎（Xdows & Tanka2）
致谢`XdowsSecurity`和`DEF（Tanka）`要是有白文件，也可以发送至 `pextechnology@qq.com`

---

## 鸣谢

- 致谢：WinDF-NES 、 Shiyi、QBZ-191、MEMZUAC、零度C-Mint
- 零度C-Mint（SouXiao引擎作者，QQ:3327867352）为SevenEngine V2（旧版本）提供了黑样本特征
- MEMZUAC（西瓜杀毒作者，QQ:3118296183）为SevenEndpoint提供了上百条行为规则
- WinDF（NES室长，QQ:3293269439）为SevenEndpoint提供了WinUI3控制台版本的Frok（暂未上线），并提供了正式、实验性和预览三个更新通道
- Shiyi（Xdows作者，QQ:2966643247）为SevenEndpoint提供了Xdows的全系列引擎
- QBZ-191（Tanka引擎作者，QQ:3862067059）为SevenEndpoint提供了Tanka2Agent

---

## 反馈与联系

若您遇到问题，请向邮箱 `pextechnology@qq.com` 汇报，也可以发送误报文件。

其中的扫描引擎和数据若有不足也请汇报；或者有更好的选择，可以告诉我们！

- SevenEndpoint官方QQ群聊：[群聊](https://qm.qq.com/q/5PTqeSIfhm)
- 个人BiliBili：`Karlmayer`
- 工作室Bilibili：`新启年工作室-NES`
- 所属工作室：`新启年工作室（NewEraStudio - NES）`
- 工作室网页：[NewEra](https://www.newera2625.top/)
- 工作室群聊：[群聊](https://qm.qq.com/q/FcNEgTxFtK)
- 个人邮箱：`pextechnology@qq.com`

——感谢使用
