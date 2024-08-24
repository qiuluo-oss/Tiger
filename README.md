# 更新日志

#### 2024.08.24 发布版本V1.0.6，修复dnslog外带bug，新增万户OA系列POC，POC数量已达150+

```
1）、万户OA TeleConferenceService XXE注入漏洞
2）、万户OA-ezOFFICE download_ftp.jsp 接口存在任意文件读取漏洞
3）、万户OA download_old.jsp 任意文件下载漏洞
4）、万户OA downloadhttp.jsp 任意文件下载漏洞
5）、万户OA fileUpload.controller 任意文件上传漏洞
6）、万户OA smartUpload.jsp 任意文件上传漏洞
7）、万户OA text2Html 任意文件读取
8）、万户协同办公平台ezoffice wpsservlet接口存在任意文件上传漏洞
9）、万户OA-contract_gd-sql注入
10）、万户OA-senddocument_import.jsp任意文件上传
```

#### 2024.08.23 发布版本V1.0.5，新增停车场后台管理系统指纹，优化通达OA、安恒下一代防火墙、万户OA、安恒明御安全网关等指纹，新增10个POC

```
1）、Adobe-ColdFusion任意文件读取漏洞CVE-2024-20767
2）、ACME Mini_httpd 任意文件读取漏洞 CVE-2018-18778
3）、Apache ActiveMQ Jolokia 后台远程代码执行漏洞 CVE-2022-41678
4）、智慧校园管理系统FileUpAd任意文件上传漏洞02
5）、用友U8 Cloud upload.jsp接口存在任意文件上传
6）、安恒 下一代防火墙 aaa_portal_auth_local_submit 存在远程命令执行漏洞
7）、万户OA DocumentEdit.jsp SQL注入漏洞
8）、万户OA DownloadServlet 任意文件读取漏洞
9）、万户OA OfficeServer.jsp 任意文件上传漏洞
10）、安恒-明御安全网关-文件上传
```

#### 2024.08.22 发布版本V1.0.4，优化Alibaba Canal、Apache APISIX 等部分指纹，新增10个POC

```
1）、Alibaba Canal 信息泄露
2）、Alibaba Canal 默认弱口令漏洞
3）、fastjson CVE-2017-18349
4）、ActiveMQ物理路径泄漏漏洞
5）、Apache ActiveMQ 弱口令
6）、Apache ActiveMQ 远程代码执行漏洞(CVE-2016-3088)
7）、AVCON-系统管理平台download.action存在任意文件读取漏洞
8）、avcon综合管理平台SQL注入漏洞
9）、Apache APISIX Dashboard 身份验证绕过漏洞（CVE-2021-45232）
10）、Apache APISIX 默认密钥漏洞（CVE-2020-13945）
```

#### 2024.08.21 发布版本V1.0.3，优化九思OA、AJ-Report等部分指纹，新增10个POC

```
1）、致远M1移动端存在未授权访问
2）、29网课交单平台epay.php存在SQL注入漏洞
3）、H3C iMC智能管理中心RCE
4）、3C环境自动监测监控系统ReadLog文件读取漏洞
5）、360天擎终端安全管理系统前台SQL注入
6）、AJ-Report开源数据大屏存在远程命令执行漏洞
7）、九思OA /jsoa/WebServiceProxy XXE漏洞
8）、APP分发签名系统index-uplog.php存在任意文件上传漏洞
9）、智联云采 SRM2.0 runtimeLog/download 任意文件读取漏洞
10）、AList云盘 未授权访问
```

#### 2024.08.20 发布版本V1.0.2，添加端口服务未授权检测

```
1）、CouchDB 未授权访问
2）、Docker 未授权访问
3）、Elasticsearch 存在未授权访问
4）、FTP 未授权访问
5）、Hadoop 未授权访问
6）、JBoss 未授权访问
7）、Jenkins 未授权访问
8）、Memcached 未授权访问
9）、mongodb 未授权访问
10）、MySQL 空口令漏洞
11）、PostgreSQL 未授权访问
12）、redis 未授权访问
13）、Rsync 未授权访问
14）、Zookeeper 未授权访问
```

#### 2024.08.19

```
1、新增漏洞：中远麒麟堡垒机admin.php 存在SQL 注入漏洞、亿赛通 电子文档安全管理系统UploadFileFromClientServiceForClient接口存在任意文件上传漏洞、致远OA M1 server RCE。
2、优化部分指纹、添加指纹信息。
```

# 前世今生

现在大多数的漏扫工具都是一股脑蜂拥而上，管你什么CMS，所有的POC都会尝试一遍。在我看来这种漏扫方式有很大的缺点：

```
1、耗时比较长。若前提我们知道目标的指纹是泛微OA，按理来说，应该只需验证泛微OA的POC即可，但所有POC都验证浪费很多时间。
2、很容易被蓝队人员发现。大批量的扫描非常容易被发现，若只是几个POC或十几个，相对几百上千个POC更不容易发觉。
```

在此背景下，Tiger应运而生，减少红队人员的时间成本和被发现的可能性。命名Tiger的原因是老虎会精准的追踪猎物、扑食猎物。

# 介绍

Tiger是一款对资产重点系统指纹识别、精准漏扫的工具。第一环节：从大量的资产中提取有用的系统(如OA、VPN、Weblogic...)；第二环节：针对收集到的资产实施精准漏扫，Tiger的漏洞库目前包含历年HW公开的POC和高危的POC。Tiger旨在帮助红队人员在信息收集期间能够快速从C段、大量杂乱的资产中精准定位到易被攻击的系统，并自动化实施精准漏扫。

![image](https://github.com/user-attachments/assets/3df0b843-69f9-4135-95b3-0dfd8ae9086c)

# 目前功能

#### 重点资产识别，内置指纹库2W+

#### 针对重点资产进行精准漏扫，内置POC库100+

#### 目录扫描

#### 端口服务未授权检测，支持14种未授权检测

# 未来计划

#### 添加更多的POC

#### 添加FUZZ，在没有找到Nday时，启用FUZZ模式，包括主动FUZZ和被动FUZZ

```
1、主动FUZZ使用爬虫爬取，使用内置的payload测试SQL注入、XSS、文件上传、RCE等。
2、被动模式是监听burpsuite的流量，使用内置的payload测试SQL注入、XSS、文件上传、RCE等。
```

#### 朝着渗透自动化方向，只需输入单位名称就可自动化完成整个渗透过程

# 参数介绍

#### tiger.exe -h

```
Usage:
  tiger [flags]
  tiger [command]

Available Commands:
  finger      tiger的指纹识别、漏洞扫描、目录扫描、端口服务未授权检测模块
  fofaext     tiger的fofa提取模块
  help        Help about any command

Flags:
      --config string   config file (default is $HOME/.tiger.yaml)
  -h, --help            help for tiger
  -t, --toggle          Help message for toggle
  -v, --version         Show version information

Use "tiger [command] --help" for more information about a command
```

![image](https://github.com/user-attachments/assets/83f92430-7c87-41c5-9b8e-a90462bc43ec)


#### tiger.exe finger -h

```
从fofa或者本地文件获取资产进行指纹识别，支持单条url识别。

Usage:
  tiger finger [flags]

Flags:
  -d, --dir             目录扫描，默认为false不开启，若为true则开启
  -f, --fip string      从fofa提取资产，进行指纹识别，仅仅支持ip或者ip段，例如：192.168.1.1 | 192.168.1.0/24
  -s, --fofa string     从fofa提取资产，进行指纹识别，支持fofa所有语法
  -h, --help            help for finger
  -a, --hip string      从hunter提取资产，进行指纹识别，仅仅支持ip或者ip段，例如：192.168.1.1 | 192.168.1.0/24
  -b, --hunter string   从hunter提取资产，进行指纹识别，支持hunter所有语法
  -l, --local string    从本地文件读取资产，进行指纹识别，支持无协议，列如：192.168.1.1:9090 | http://192.168.1.1:9090
  -o, --output string   输出所有结果，当前仅支持json和xlsx后缀的文件。
  -v, --poc             精准漏扫，默认false不开启，只进行重点资产收集；若为true则开启
  -P, --port_server     端口服务未授权扫描，默认为false不开启，若为true则开启
  -p, --proxy string    指定访问目标时的代理，支持http代理和socks5，例如：http://127.0.0.1:8080、socks5://127.0.0.1:8080
  -t, --thread int      指纹识别线程大小。 (default 100)
  -u, --url string      识别单个目标。

Global Flags:
      --config string   config file (default is $HOME/.tiger.yaml)
```

![image](https://github.com/user-attachments/assets/8066a968-7f96-468b-be39-39ea3921cbec)


# 使用

#### 重点资产识别

1、若需要对FAFO或HUNTER的资产做指纹识别，需在config.ini中配置FAFO和HUNTER的KEY

![d5d2ff038adbc81c69dc731ba8e782d](https://github.com/user-attachments/assets/3aee75a1-daa7-444e-b55f-9c65be810ed1)

2、对FOFA收集的资产做指纹识别：

```
.\tiger.exe finger -s 'domain="hnys.edu.cn" || cname_domain="hnys.edu.cn" || cname="hnys.edu.cn" ||cert="hnys.edu.cn" || cert.subject="河南艺术职业学院" || cert.subject.org="河南艺术职业学院" ||cert.subject.cn="hnys.edu.cn" || icp="豫ICP备14014451号"'
```

![23fc95932f9299d453082b631092fb2](https://github.com/user-attachments/assets/9bf64144-f6c8-44c8-923c-08668611c6f1)


3、对本地的资产做指纹识别：

```
.\tiger.exe finger -l .\target.txt
```

![image](https://github.com/user-attachments/assets/be91fa13-8cb6-477b-a690-ef191a34d39b)

#### 精准漏扫

1、精准漏扫，默认false，需要使用时指定：`-v true` 对目标识别出来的指纹做对应的漏扫，举例若目标是泛微OA，只会使用泛微OA的POC做漏扫，减少被发现的可能性；命令：

```
.\tiger.exe finger -l .\target.txt -v true
```

![eb28798cf27a589cdfbc6f9613d5d27](https://github.com/user-attachments/assets/8ca4d123-5340-4111-adff-5001c49e8036)

#### 目录扫描

1、内置150个目录，包括常用的未授权、备份文件、sql文件等，默认为false，需要使用时指定：`-d true`，当目标是域名时，工具会自动获取"."前后的域名字符串作为目录字典，例如：https://www.baidu.com/， 工具会自动获取www.zip、www.7z、www.bak、www.tar.gz、www.rar、baidu.zip、baidu.7z、baidu.bak、baidu.tar.gz、baidu.rar；命令：

```
.\tiger.exe finger -l .\dir.txt -d true
```

![image](https://github.com/user-attachments/assets/c3dbbbc1-e6f1-4a27-a851-9062b61a760c)

#### 端口服务未授权检测

1、端口服务未授权检测默认关闭，需要开启时指定参数：`-P true`，支持14种未授权检测，详情如下

```
1）、CouchDB 未授权访问
2）、Docker 未授权访问
3）、Elasticsearch 存在未授权访问
4）、FTP 未授权访问
5）、Hadoop 未授权访问
6）、JBoss 未授权访问
7）、Jenkins 未授权访问
8）、Memcached 未授权访问
9）、mongodb 未授权访问
10）、MySQL 空口令漏洞
11）、PostgreSQL 未授权访问
12）、redis 未授权访问
13）、Rsync 未授权访问
14）、Zookeeper 未授权访问
```

2、对FAFO收集的资产进行端口服务未授权检测，命令：

```
.\tiger.exe finger -s ip="x.x.x.x/24" -P true
```

![image](https://github.com/user-attachments/assets/76724cfc-a00f-4a68-b572-147d40f0d645)


#### 输出保存格式

1、保存json格式，指定参数`-o`，输出文件名`xxx.json`

```
.\tiger.exe finger -s 'domain="hnys.edu.cn" || cname_domain="hnys.edu.cn" || cname="hnys.edu.cn" ||cert="hnys.edu.cn" || cert.subject="河南艺术职业学院" || cert.subject.org="河南艺术职业学院" ||cert.subject.cn="hnys.edu.cn" || icp="豫ICP备14014451号"' -o test.json
```

![e92117723bab3e6e5e348e988bf3e3b](https://github.com/user-attachments/assets/88846d8f-b226-4b25-a8e6-060396a09819)


2、保存xlsx格式，指定参数`-o`，输出文件名`xxx.xlsx`

```
.\tiger.exe finger -s 'domain="hnys.edu.cn" || cname_domain="hnys.edu.cn" || cname="hnys.edu.cn" ||cert="hnys.edu.cn" || cert.subject="河南艺术职业学院" || cert.subject.org="河南艺术职业学院" ||cert.subject.cn="hnys.edu.cn" || icp="豫ICP备14014451号"' -o test.xlsx
```

![938a0f6f97b8a0d92b6abdea672c3af](https://github.com/user-attachments/assets/57bb453a-ae86-4dea-a115-fc4f4814b635)


# POC支持清单

| 分类       | 应用                        | 漏洞名称                                                     |
| ---------- | --------------------------- | ------------------------------------------------------------ |
| Framework  | Laravel                     | CVE-2017-16894                                               |
|            |                             | CVE-2021-3129                                                |
|            |                             | CVE-2022-40734                                               |
|            | PHP                         | PHP 8.1.0-dev 开发版本后门                                   |
|            |                             | PHP phpinfo() 信息泄露                                       |
|            |                             | PHP文件包含漏洞(利用phpinfo)                                 |
|            | Shiro                       | 默认key                                                      |
|            | Spring                      | CVE-2018-1273                                                |
|            |                             | CVE-2020-5410                                                |
|            |                             | CVE-2024-40348                                               |
|            | Thinkphp                    | CNVD-2018-24942                                              |
|            |                             | thinkphp2.x rce                                              |
|            |                             | thinkphp3.2.x rce                                            |
|            |                             | thinkphp_index_showid_rce                                    |
|            |                             | ThinkPHP5 SQL Injection Vulnerability                        |
|            |                             | thinkphp_pay_orderid_sqli                                    |
|            |                             | thinkphp_multi_sql_leak                                      |
|            |                             | thinkphp_driver_display_rce                                  |
|            |                             | thinkphp_invoke_func_code_exec                               |
|            | nodejs                      | CVE-2021-21315                                               |
|            |                             | CVE-2017-14849                                               |
| middleware | nginx                       | nginxWebUI远程命令执行                                       |
|            |                             | Nginx 解析漏洞                                               |
|            | Tomcat                      | CVE-2017-12615                                               |
|            |                             | CVE-2019-0232                                                |
|            |                             | CVE-2024-21733                                               |
|            |                             | Apache Tomcat 弱口令                                         |
|            | Weblogic                    | CVE-2014-4210                                                |
|            | ActiveMQ                    | 物理路径泄漏漏洞                                             |
|            |                             | 弱口令                                                       |
|            |                             | 远程代码执行漏洞(CVE-2016-3088)                              |
|            |                             | CVE-2022-41678                                               |
|            | ACME Mini_httpd             | 任意文件读取漏洞 CVE-2018-18778                              |
| port       | CouchDB                     | 5984端口CouchDB未授权访问                                    |
|            | Docker                      | 2375端口Docker未授权访问                                     |
|            | Elasticsearch               | 9200端口Elasticsearch未授权访问                              |
|            | ftp                         | 21端口ftp未授权访问                                          |
|            | Hadoop                      | 50070端口Hadoop未授权访问                                    |
|            | JBoss                       | 8080端口JBoss未授权访问                                      |
|            | Jenkins                     | 8080端口Jenkins未授权访问                                    |
|            | Memcached                   | 11211端口Memcached未授权访问                                 |
|            | MongoDB                     | 27017端口MongoDB未授权访问                                   |
|            | MySQL                       | 3306端口MySQL空口令                                          |
|            | PostgreSQL                  | 5432端口PostgreSQL未授权访问                                 |
|            | Redis                       | 6379端口redis未授权访问                                      |
|            | Rsync                       | 873端口Rsync未授权访问                                       |
|            | Zookeeper                   | 2181端口Zookeeper未授权访问                                  |
| redteam    | 用友畅捷通                  | 用友畅捷通 SQL注入（site_id延时注入）                        |
|            |                             | 畅捷通T+ DownloadProxy.aspx 任意文件读取漏洞                 |
|            |                             | 用友畅捷通T+GetStoreWarehouseByStore RCE                     |
|            |                             | 畅捷通T+ RecoverPassword.aspx 管理员密码修改漏洞             |
|            | dahua                       | 大华智慧园区综合管理平台devicePoint_addImgIco任意文件上传漏洞 |
|            |                             | 大华DSS itcBulletin SQL 注入漏洞                             |
|            |                             | 大华智慧园区综合管理平台 任意文件读取漏洞                    |
|            |                             | 大华智慧园区任意密码读取漏洞                                 |
|            |                             | 大华智慧园区综合管理平台 video 任意文件上传漏洞              |
|            | druid                       | Alibaba Druid Monitor 弱口令                                 |
|            |                             | Alibaba Druid Monitor 未授权访问                             |
|            |                             | Apache Druid 未授权访问                                      |
|            | finereport                  | CNVD-2018-04757                                              |
|            | fastjson                    | CVE-2017-18349                                               |
|            | 中远麒麟堡垒机              | 中远麒麟堡垒机admin.php 存在SQL 注入漏洞                     |
|            | H3C                         | H3C IMC dynamiccontent.properties.xhtm 远程命令执行          |
|            |                             | H3C多系列路由器前台RCE漏洞                                   |
|            |                             | H3C iMC智能管理中心 RCE                                      |
|            | HIKVISION                   | HIKVISION 综合安防管理平台env信息泄露                        |
|            |                             | 海康威视isecure center 综合安防管理平台存在任意文件上传漏洞  |
|            |                             | HIKVISION视频编码设备任意文件下载                            |
|            | 宏景eHR                     | 宏景eHR SQL注入                                              |
|            |                             | 宏景eHR文件上传                                              |
|            | 金和OA                      | 金和OA C6 UploadFileEditor.aspx存在sql注入漏洞               |
|            | 金蝶云星空                  | 金蝶云星空 CommonFileserver 任意文件读取                     |
|            |                             | 金蝶云星空Kingdee- erp-Unserialize-RCE漏洞                   |
|            | 蓝凌OA                      | 蓝凌OA custom.jsp 任意文件读取漏洞                           |
|            |                             | 蓝凌OA treexml.tmpl命令执行                                  |
|            | Nacos                       | Nacos 弱密码                                                 |
|            |                             | 开启授权后identity硬编码绕过                                 |
|            |                             | jwt secret key 硬编码绕过                                    |
|            |                             | Nacos 未授权访问                                             |
|            |                             | nacos-Sync 未授权                                            |
|            | 企望制造ERP                 | 企望制造ERP_comboxstore.action远程命令执行漏洞               |
|            | Hytec Inter HWL-2511-SS     | Hytec Inter HWL-2511-SS popen.cgi命令注入                    |
|            | 致远OA                      | 致远OA A6 sql注入漏洞                                        |
|            |                             | 致远OA A8 htmlofficeservlet 任意文件上传漏洞                 |
|            |                             | 致远OA getSessionList.jsp Session泄漏漏洞(后台可getshell)    |
|            |                             | 致远OA Session泄露(thirdpartyController.do)漏洞              |
|            |                             | 致远OA M1 server RCE                                         |
|            |                             | 致远M1移动端存在未授权访问                                   |
|            | 亿赛通 电子文档安全管理系统 | UploadFileFromClientServiceForClient接口存在任意文件上传漏洞 |
|            | 深信服                      | 深信服SG上网管理系统任意文件读取                             |
|            |                             | 深信服应用交付报表系统 文件读取                              |
|            |                             | 深信服应用交付管理系统 RCE                                   |
|            | 360天擎                     | 数据库信息泄露漏洞                                           |
|            |                             | 360天擎终端安全管理系统前台SQL注入                           |
|            |                             | 天擎 rptsvr 任意文件上传漏洞                                 |
|            |                             | 360新天擎终端安全管理系统信息泄露                            |
|            |                             | 360天擎终端安全管理系统前台SQL注入                           |
|            | 通达OA                      | 通达OA sql注入(/general/reportshop/utils/get_datas.php)      |
|            |                             | 通达OA v11.6 insert SQL注入漏洞                              |
|            |                             | 通达OA v11.9 getdata 任意命令执行漏洞                        |
|            |                             | 通达OA v2017 video_file.php 任意文件下载漏洞                 |
|            | 泛微                        | 泛微Weaver E-Office9前台文件包含                             |
|            |                             | 泛微E-Office9文件上传漏洞                                    |
|            |                             | 泛微E-Cology9 WorkPlanService 前台SQL注入漏洞(XVE-2024-18112) |
|            |                             | 泛微运维平台存在任意管理员用户创建漏洞                       |
|            | 九思OA                      | /jsoa/WebServiceProxy XXE漏洞                                |
|            | 用友NC                      | 用友nc-cloud RCE                                             |
|            |                             | 用友NC-Cloud 远程命令执行                                    |
|            |                             | 用友GRP-U8存在信息泄露                                       |
|            |                             | 用友时空 KSOA servletimagefield 文件 sKeyvalue 参数SQL 注入  |
|            |                             | 用友 NC Cloud jsinvoke 任意文件上传                          |
|            |                             | 用友NCfileupload命令执行漏洞                                 |
|            |                             | 用友 NC NCFindWeb 任意文件读取漏洞                           |
|            |                             | NC bsh.servlet.BshServlet 远程命令执行漏洞                   |
|            |                             | 用友U8 Cloud upload.jsp接口存在任意文件上传                  |
|            | 禅道                        | 禅道16.5 SQL注入(CNVD-2022-42853)                            |
|            |                             | 禅道11.6版本任意文件读取漏洞                                 |
|            | 安恒 下一代防火墙           | aaa_portal_auth_local_submit 存在远程命令执行漏洞            |
|            | 万户OA                      | 万户OADocumentEdit.jsp SQL注入漏洞                           |
|            |                             | 万户OADownloadServlet 任意文件读取漏洞                       |
|            |                             | 万户OA TeleConferenceService XXE注入漏洞                     |
|            |                             | 万户OA-ezOFFICE download_ftp.jsp 接口存在任意文件读取漏洞    |
|            |                             | 万户OA download_old.jsp 任意文件下载漏洞                     |
|            |                             | 万户OA downloadhttp.jsp 任意文件下载漏洞                     |
|            |                             | 万户OA fileUpload.controller 任意文件上传漏洞                |
|            |                             | 万户OA smartUpload.jsp 任意文件上传漏洞                      |
|            |                             | 万户OA text2Html 任意文件读取                                |
|            |                             | 万户协同办公平台ezoffice wpsservlet接口存在任意文件上传漏洞  |
|            |                             | 万户OA-contract_gd-sql注入                                   |
|            |                             | 万户OA-senddocument_import.jsp任意文件上传                   |
|            |                             | OfficeServer.jsp 任意文件上传漏洞                            |
|            | 安恒-明御安全网关           | 文件上传                                                     |
| web        | Chamilo                     | Chamilo additional_webservices.php RCE                       |
|            | Eramba                      | Eramba任意代码执行                                           |
|            | 红海 EHR                    | 红海 EHR 系统pc.mob sql 注入漏洞                             |
|            | LiveBOS                     | LiveBOS ShowImage.do 任意文件读取漏洞                        |
|            | Metabase                    | Metabase远程命令执行漏洞 (CVE-2023-38646)                    |
|            | Apache OFBiz                | Apache OFBiz代码执行(CVE-2024-38856) RCE                     |
|            | 1Panel                      | 1Panel loadfile后台文件读取漏洞                              |
|            | 契约锁电子签章平台          | 契约锁电子签章平台add远程命令执行漏洞                        |
|            |                             | 契约锁电子签章平台ukeysign存在远程命令执行漏洞               |
|            | Smartbi                     | Smartbi 默认用户登陆绕过漏洞                                 |
|            | 智慧校园安校易管理系统      | FileUpAd任意文件上传漏洞01                                   |
|            |                             | FileUpAd任意文件上传漏洞02                                   |
|            | 云时空-社会化商业ERP系统    | 云时空-社会化商业ERP系统session泄露 接管后台                 |
|            | 29网课交单平台              | epay.php存在SQL注入漏洞                                      |
|            | 3C环境自动监测监控系统      | ReadLog文件读取漏洞                                          |
|            | AJ-Report                   | 开源数据大屏存在远程命令执行漏洞                             |
|            | APP分发签名系统             | index-uplog.php存在任意文件上传漏洞                          |
|            | 智联云采 SRM2.0             | runtimeLog/download 任意文件读取漏洞                         |
|            | AList云盘                   | 未授权访问                                                   |
|            | Alibaba Canal               | 信息泄露                                                     |
|            |                             | 默认弱口令漏洞                                               |
|            | Apache APISIX               | 身份验证绕过漏洞（CVE-2021-45232）                           |
|            |                             | 默认密钥漏洞（CVE-2020-13945）                               |
|            | AVCON-系统管理平台          | download.action存在任意文件读取漏洞                          |
|            |                             | SQL注入漏洞                                                  |
|            | Adobe-ColdFusion            | 任意文件读取漏洞CVE-2024-20767                               |



# 免责声明：

本软件/工具仅供教育和研究目的使用。未经授权用于非法或恶意活动的行为是严格禁止的。开发者对任何由于使用本工具而引发的误用或法律后果概不负责。使用本工具即表示您同意遵守所有适用的法律法规。请负责任和合乎道德地使用本工具。

# 加入安全交流群

![3cc96cdb9cdf4d1b3cb37ce88293b73](https://github.com/user-attachments/assets/54db88b7-9ac9-44fa-8ef9-2df0267c8c43)

