# CF-Workers-CheckSocks5

一个基于 Cloudflare Workers 的高性能代理检测服务，支持 SOCKS5 和 HTTP 代理的连通性测试和 IP 信息查询。

## ✨ 功能特性

- 🚀 **代理检测**：支持 SOCKS5 和 HTTP 代理的连通性测试
- 🌍 **IP 信息查询**：获取 IP 地址的地理位置、ASN、风险评分等详细信息
- 🔒 **安全认证**：支持用户名/密码认证的代理
- 📱 **响应式界面**：现代化的 Web 界面，支持移动端访问
- 🎯 **域名解析**：自动解析域名并支持多 IP 切换
- ⚡ **高性能**：基于 Cloudflare Workers 边缘计算平台
- 🔧 **易部署**：一键部署，无需服务器维护

## 🏃 快速开始

### 在线体验

访问在线演示：[Demo](https://check.socks5.cmliussss.net)

## 🚀 部署方式

- **Workers** 部署：复制 [_worker.js](https://github.com/cmliu/CF-Workers-CheckSocks5/blob/main/_worker.js) 代码，`保存并部署`即可
- **Pages** 部署：`Fork` 后 `连接GitHub` 一键部署即可

## 🔧 环境变量配置

在 Cloudflare Workers 控制台中设置以下环境变量：

| 变量名 | 说明 | 示例 | 必需 |
|--------|------|------|------|
| `TOKEN` | API 访问令牌，用于保护接口（设置`TOKEN`之后，首页会变成**nginx**，避免变成公共服务） | `your-secret-token` | 否 |
| `URL302` | 302跳转伪装首页 | `https://example.com` | 否 |
| `URL` | 反向代理伪装首页 | `https://example.com` | 否 |
| `ICO` | 网站图标 URL | `https://example.com/favicon.ico` | 否 |
| `IMG` | 背景图片 URL，支持多个（用逗号分隔） | `https://example.com/bg.jpg` | 否 |
| `BEIAN` | 网站备案信息 | `ICP备案号` | 否 |

## 📖 API 文档

### 代理检测接口

**端点**：`/check`

**请求方式**：`GET`

**参数**：
- `proxy`：代理 URL（支持 socks5:// 和 http:// 前缀）
- `token`：访问令牌（如果设置了 TOKEN 环境变量）

**代理 URL 格式**：
```
# SOCKS5 代理
socks5://username:password@host:port
socks5://host:port

# HTTP 代理
http://username:password@host:port
http://host:port

# IPv6 地址需要用方括号括起来
socks5://username:password@[2001:db8::1]:1080
```

**响应示例**：
```json
{
    "success": true,
    "proxy": "socks5://username:password@host:port",
    "ip": "8.8.8.8",
    "rir": "APNIC",
    "is_bogon": false,
    "is_mobile": false,
    "is_satellite": false,
    "is_crawler": false,
    "is_datacenter": true,
    "is_tor": false,
    "is_proxy": false,
    "is_vpn": true,
    "is_abuser": false,
    "datacenter": {
        "network": "8.213.144.0/20",
        "datacenter": "alibaba"
    },
    "company": {
        "name": "Alibabacom Singapore E-Commerce Private Limited a",
        "abuser_score": "0.01 (Elevated)",
        "domain": "alibabacloud.com",
        "type": "hosting",
        "network": "8.213.128.0 - 8.213.159.255",
        "whois": "https://api.ipapi.is/?whois=8.213.128.0"
    },
    "abuse": {
        "name": "ABUSE ASEPLSG",
        "address": "1 Raffles Place # 59-00 One Raffles Place, Tower One Singapore, Singapore",
        "email": "abuse@alibaba-inc.com",
        "phone": "+000000000"
    },
    "asn": {
        "asn": 45102,
        "abuser_score": "0.0015 (Low)",
        "route": "8.213.144.0/20",
        "descr": "ALIBABA-CN-NET Alibaba US Technology Co., Ltd., CN",
        "country": "cn",
        "active": true,
        "org": "Alibaba (US) Technology Co., Ltd.",
        "domain": "alibaba.com",
        "abuse": "didong.jc@alibaba-inc.com",
        "type": "business",
        "updated": "2021-10-27",
        "rir": "APNIC",
        "whois": "https://api.ipapi.is/?whois=AS45102"
    },
    "location": {
        "is_eu_member": false,
        "calling_code": "82",
        "currency_code": "KRW",
        "continent": "AS",
        "country": "South Korea",
        "country_code": "KR",
        "state": "서울특별시",
        "city": "Seoul",
        "latitude": 37.566,
        "longitude": 126.9784,
        "zip": "04524",
        "timezone": "Asia/Seoul",
        "local_time": "2025-05-27T15:52:11+09:00",
        "local_time_unix": 1748328731,
        "is_dst": false
    },
    "elapsed_ms": 1.07,
    "timestamp": "2025-05-27T06:52:11.856Z"
}
```

## 💡 使用示例

### cURL 示例

```bash
# 检测 SOCKS5 代理
curl "https://your-worker.workers.dev/check?proxy=socks5://user:pass@proxy.example.com:1080"

# 检测 HTTP 代理
curl "https://your-worker.workers.dev/check?proxy=http://proxy.example.com:8080"

```

## 🔍 字段说明

### 风险评估字段

- `is_datacenter`：是否为数据中心 IP
- `is_proxy`：是否为代理服务器
- `is_vpn`：是否为 VPN 服务器
- `is_tor`：是否为 Tor 出口节点
- `is_crawler`：是否为网络爬虫
- `is_abuser`：是否有滥用行为记录
- `abuser_score`：滥用风险评分（0-1，数值越高风险越大）

### 地理位置字段

- `country_code`：国家代码（ISO 3166-1 alpha-2）
- `city`：城市名称

### ASN 字段

- `asn`：自治系统编号
- `org`：所属组织/ISP 名称

## 🛠️ 技术架构

- **运行环境**：Cloudflare Workers
- **网络协议**：支持 SOCKS5 和 HTTP CONNECT
- **DNS 解析**：Cloudflare DNS over HTTPS
- **IP 信息 API**：ipapi.is

## 📄 许可证

本项目采用 GNU General Public License v3.0 - 查看 [LICENSE](LICENSE) 文件了解详情

## 🙏 致谢

- [Cloudflare Workers](https://workers.cloudflare.com/) - 无服务器计算平台
- [ipapi.is](https://ipapi.is/) - IP 地理位置查询服务
- [Cloudflare DNS](https://cloudflare-dns.com/) - DNS over HTTPS 服务
