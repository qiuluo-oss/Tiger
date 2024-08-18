# 前世今生
现在大多数的漏扫工具都是一股脑蜂拥而上，管你什么CMS，所有的POC都会尝试一遍。在我看来这种漏扫方式有很大的缺点：

1、耗时比较长。若前提我们知道目标的指纹是泛微OA，按理来说，应该只需验证泛微OA的POC即可，但所有POC都验证浪费很多时间。

2、很容易被蓝队人员发现。大批量的扫描非常容易被发现，若只是几个POC或十几个，相对几百上千个POC更不容易发觉。

在此背景下，Tiger应运而生，减少红队人员的时间成本和被发现的可能性。命名Tiger的原因是老虎会精准的追踪猎物、扑食猎物。

# 介绍
Tiger是一款对资产重点系统指纹识别、精准漏扫的工具。第一环节：从大量的资产中提取有用的系统(如OA、VPN、Weblogic...)；第二环节：针对收集到的资产实施精准漏扫，Tiger的漏洞库目前包含历年HW公开的POC和高危的POC。Tiger旨在帮助红队人员在信息收集期间能够快速从C段、大量杂乱的资产中精准定位到易被攻击的系统，并自动化实施精准漏扫。

![image](https://github.com/user-attachments/assets/3df0b843-69f9-4135-95b3-0dfd8ae9086c)

# 目前功能
### 重点资产识别，内置指纹库2W+
### 针对重点资产进行精准漏扫，内置POC库100+
### 目录扫描

# 未来计划
### 添加更多的POC
### 添加FUZZ，在没有找到Nday时，启用FUZZ模式，包括主动FUZZ和被动FUZZ
1、主动FUZZ使用爬虫爬取，使用内置的payload测试SQL注入、XSS、文件上传、RCE等。

2、被动模式是监听burpsuite的流量，使用内置的payload测试SQL注入、XSS、文件上传、RCE等。

### 朝着渗透自动化方向，只需输入单位名称就可自动化完成整个渗透过程

# 参数介绍
## tiger.exe -h

![image](https://github.com/user-attachments/assets/d538afd0-bf2e-4f89-94a7-5c9830ae888f)

## tiger.exe finger -h

![image](https://github.com/user-attachments/assets/39a04ae2-dd2f-4f72-b31c-4b79c2fdc6ef)

# 使用
### 重点资产识别
1、若需要对FAFO或HUNTER的资产做指纹识别，需在config.ini中配置FAFO和HUNTER的KEY。

2、对本地的资产做指纹识别：.\tiger.exe finger -l .\target.txt

![image](https://github.com/user-attachments/assets/be91fa13-8cb6-477b-a690-ef191a34d39b)

### 精准漏扫
1、精准漏扫，默认false，需要使用时指定：-v true 对目标识别出来的指纹做对应的漏扫，举例若目标是泛微OA，只会使用泛微OA的POC做漏扫，减少被发现的可能性；命令：.\tiger.exe finger -l .\target.txt -v true

![eb28798cf27a589cdfbc6f9613d5d27](https://github.com/user-attachments/assets/8ca4d123-5340-4111-adff-5001c49e8036)

### 目录扫描
1、内置150个目录，包括常用的未授权、备份文件、sql文件等，默认为false，需要使用时指定：-d true；当目标是域名时，工具会自动获取"."前后的域名字符串作为目录字典，例如：https://www.baidu.com/， 工具会自动获取www.zip、www.7z、www.bak、www.tar.gz、www.rar、baidu.zip、baidu.7z、baidu.bak、baidu.tar.gz、baidu.rar；命令：.\tiger.exe finger -l .\dir.txt -d true

![image](https://github.com/user-attachments/assets/c3dbbbc1-e6f1-4a27-a851-9062b61a760c)

# 免责声明：
本软件/工具仅供教育和研究目的使用。未经授权用于非法或恶意活动的行为是严格禁止的。开发者对任何由于使用本工具而引发的误用或法律后果概不负责。使用本工具即表示您同意遵守所有适用的法律法规。请负责任和合乎道德地使用本工具。
