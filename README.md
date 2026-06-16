# WHOIS-PHP 查询 API

一个基于 PHP 原生 Socket 通信的 WHOIS 域名信息查询接口，内置高效的 IANA 路由机制和跨域（CORS）支持。
**数据来源于公开Whois信息，仅供参考。**

## 版本信息
- **当前版本**：v1.0.0 稳定版
## 接口基本信息
接口文档：[https://whois.tiking.top/docs](https://whois.tiking.top/docs)
```
请求方式：GET
返回格式：application/json
```
成功响应 JSON 示例 (200 OK)
```
{
  "status": 1,
  "data": {
    "domain": "example.com",
    "domain_suffix": "com",
    "is_available": 0,
    "raw": "Domain Name: EXAMPLE.COM\nRegistry Domain ID: 233226173_DOMAIN_COM-VRSN...",
    "info": {
      "registrar_name": "RESERVED-Internet Assigned Numbers Authority",
      "registrant_name": "",
      "registrant_email": "",
      "whois_server": "whois.verisign-grs.com",
      "creation_time": "1995-08-14 00:00:00",
      "expiration_time": "2027-08-13 00:00:00",
      "creation_days": 11263,
      "valid_days": 424,
      "is_expire": 0,
      "domain_status": [
        "clientDeleteProhibited",
        "clientTransferProhibited"
      ],
      "name_server": [
        "A.IANA-SERVERS.NET",
        "B.IANA-SERVERS.NET"
      ]
    }
  }
}
```
失败（缺参数）响应 JSON 示例
```
{
  "status": 0,
  "error": "Domain parameter is required."
}
```
无参数默认302 => https://whois.tiking.top/docs
自定义302需自行更改whois.php
## 运行环境
- **操作系统**：Linux / Windows (推荐 CentOS / Ubuntu)
- **Web 服务器**：Nginx (推荐) 或 Apache
- **PHP 版本**：PHP 7.4 及以上（兼容 PHP 8.x）
- **PHP 核心组件依赖**：需要开启 `fsockopen` 或 `stream_socket_client` 函数（用于 43 端口 Socket 通信）。

## 使用的第三方服务
本项目保持高度独立性与轻量化，**未接入任何第三方商业付费 WHOIS 接口**。
- **上游服务依赖**：直接连接 **IANA (Internet Assigned Numbers Authority)** 官方权威根服务器 (`whois.iana.org`) 及其下属的各顶级域名注册局（如 Verisign、CNNIC 等）公开的 43 端口 WHOIS 服务器。

## 部署方法与伪静态配置

### 1. 源码放置
将后端代码放置在您服务器的 Web 目录下（例如宝塔面板路径）：
```text
/www/wwwroot/whois/
└── whois.php      # 核心后端 API 源码
```

### 2.配置美化路径伪静态 

```text
Nginx:
location /whois/v1/ { 
    rewrite ^/whois/v1/?$ /whois/whois.php  last;
}

Apache:
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteRule ^whois/v1/?$ whois/whois.php [QSA,L]
```
## 开源协议
本项目基于 MIT License 协议开源
