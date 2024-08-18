# 介绍
Tiger是一款对资产重点系统指纹识别、精准漏扫的工具。第一环节：从大量的资产中提取有用的系统(如OA、VPN、Weblogic...)；第二环节：针对收集到的资产实施精准漏扫，Tiger的漏洞库目前包含历年HW公开的POC和高危的POC。Tiger旨在帮助红队人员在信息收集期间能够快速从C段、大量杂乱的资产中精准定位到易被攻击的系统，并自动化实施精准漏扫。

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
Usage:

  tiger [flags]
  
  tiger [command]

Available Commands:

  finger      tiger的指纹识别、漏洞扫描、目录扫描模块
  
  fofaext     tiger的fofa提取模块
  
  help        Help about any command

Flags:
      --config string   config file (default is $HOME/.tiger.yaml)
      
  -h, --help            help for tiger
  
  -t, --toggle          Help message for toggle
  
  -v, --version         Show version information

## tiger.exe finger -h
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
  
  -p, --proxy string    指定访问目标时的代理，支持http代理和socks5，例如：http://127.0.0.1:8080、socks5://127.0.0.1:8080
  -t, --thread int      指纹识别线程大小。 (default 100)
  -u, --url string      识别单个目标。

# 使用
### 重点资产识别
