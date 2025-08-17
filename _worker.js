/*
 * =================================================================================
 * Cloudflare Sockets API (TCP)
 * ---------------------------------------------------------------------------------
 * This code utilizes the 'cloudflare:sockets' API for direct TCP connections.
 * It is essential for the SOCKS5 and HTTP proxy checking functionalities.
 * To enable this, you must add the following compatibility flag to your
 * wrangler.toml file (if you use one):
 *
 * compatibility_flags = [ "streams_enable_constructors", "nodejs_compat" ]
 *
 * Or ensure your Pages project has the necessary compatibility flags enabled.
 * Learn more at: https://developers.cloudflare.com/workers/runtime-apis/sockets/
 * =================================================================================
 */
import { connect } from 'cloudflare:sockets';

// 全局变量区
let 临时TOKEN, 永久TOKEN;
let parsedSocks5Address = {};

// --- 密码验证相关常量 ---
const AUTH_COOKIE_NAME = '__proxy_check_auth';

/**
 * 助手函数：SHA-256 哈希
 * @param {string} text - 要哈希的文本
 * @returns {Promise<string>} - 哈希后的十六进制字符串
 */
async function sha256(text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * 助手函数：创建登录页面
 * @param {boolean} hasError - 是否显示错误信息
 * @returns {Response}
 */
function createLoginPage(hasError = false) {
    const errorMessage = hasError ? '<p class="error">密码错误，请重试。</p>' : '';
    const html = `
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>需要身份验证</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: #f0f2f5; }
            .login-container { background: #fff; padding: 40px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); text-align: center; max-width: 320px; width: 90%; }
            h1 { margin-top: 0; color: #333; }
            input[type="password"] { width: 100%; padding: 12px; margin: 15px 0; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
            button { width: 100%; padding: 12px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
            button:hover { background-color: #0056b3; }
            .error { color: #d93025; margin-bottom: 10px; font-weight: bold; }
        </style>
    </head>
    <body>
        <div class="login-container">
            <h1>访问受限</h1>
            <p>请输入密码以继续</p>
            ${errorMessage}
            <form method="post">
                <input type="password" name="password" placeholder="请输入密码" required autofocus>
                <button type="submit">登录</button>
            </form>
        </div>
    </body>
    </html>`;
    return new Response(html, { headers: { 'Content-Type': 'text/html;charset=UTF-8' }, status: 401 });
}


/**
 * 主应用逻辑（您原来的 fetch 函数）
 * @param {Request} request
 * @param {object} env
 * @returns {Promise<Response>}
 */
async function handleApplication(request, env) {
    const url = new URL(request.url);
    const UA = request.headers.get('User-Agent') || 'null';
    const currentDate = new Date();
    const timestamp = Math.ceil(currentDate.getTime() / (1000 * 60 * 60 * 12)); // 每12小时一个时间戳
    临时TOKEN = await 双重哈希(url.hostname + timestamp + UA);
    永久TOKEN = env.TOKEN || 临时TOKEN;
    if (url.pathname.toLowerCase() === "/check") {
        if (env.TOKEN) {
            if (!url.searchParams.has('token') || url.searchParams.get('token') !== 永久TOKEN) {
                return new Response(JSON.stringify({
                    status: "error",
                    message: `IP查询失败: 无效的TOKEN`,
                    timestamp: new Date().toISOString()
                }, null, 4), {
                    status: 403,
                    headers: {
                        "content-type": "application/json; charset=UTF-8",
                        'Access-Control-Allow-Origin': '*'
                    }
                });
            }
        }
        if (url.searchParams.has("socks5")) {
            const 代理参数 = url.searchParams.get("socks5");
            return await 检测SOCKS5代理(代理参数);
        } else if (url.searchParams.has("http")) {
            const 代理参数 = url.searchParams.get("http");
            return await 检测HTTP代理(代理参数);
        } else if (url.searchParams.has("proxy")) {
            const 代理参数 = url.searchParams.get("proxy");
            if (代理参数.toLowerCase().startsWith("socks5://")) {
                return await 检测SOCKS5代理(代理参数);
            } else if (代理参数.toLowerCase().startsWith("http://")) {
                return await 检测HTTP代理(代理参数);
            }
        }
        // 如果没有提供有效的代理参数，返回错误响应
        return new Response(JSON.stringify({
            success: false,
            error: "请提供有效的代理参数：socks5、http 或 proxy"
        }, null, 2), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
        });
    } else if (url.pathname.toLowerCase() === '/ip-info') {
        if (!url.searchParams.has('token') || (url.searchParams.get('token') !== 临时TOKEN) && (url.searchParams.get('token') !== 永久TOKEN)) {
            return new Response(JSON.stringify({
                status: "error",
                message: `IP查询失败: 无效的TOKEN`,
                timestamp: new Date().toISOString()
            }, null, 4), {
                status: 403,
                headers: {
                    "content-type": "application/json; charset=UTF-8",
                    'Access-Control-Allow-Origin': '*'
                }
            });
        }
        const ip = url.searchParams.get('ip') || request.headers.get('CF-Connecting-IP');
        try {
            const data = await getIpInfo(ip);
            // 返回数据给客户端，并添加CORS头
            return new Response(JSON.stringify(data, null, 4), {
                headers: {
                    "content-type": "application/json; charset=UTF-8",
                    'Access-Control-Allow-Origin': '*'
                }
            });
        } catch (error) {
            console.error("IP查询失败:", error);
            return new Response(JSON.stringify({
                status: "error",
                message: `IP查询失败: ${error.message}`,
                code: "API_REQUEST_FAILED",
                query: ip,
                timestamp: new Date().toISOString(),
                details: {
                    errorType: error.name,
                    stack: error.stack ? error.stack.split('\n')[0] : null
                }
            }, null, 4), {
                status: 500,
                headers: {
                    "content-type": "application/json; charset=UTF-8",
                    'Access-Control-Allow-Origin': '*'
                }
            });
        }
    }
    if (env.TOKEN) {
        return new Response(await nginx(), {
            headers: {
                'Content-Type': 'text/html; charset=UTF-8',
            },
        });
    } else if (env.URL302) return Response.redirect(env.URL302, 302);
    else if (env.URL) return await 代理URL(env.URL, url);
    else {
        const 网站图标 = env.ICO ? `<link rel="icon" href="${env.ICO}" type="image/x-icon">` : '';
        const 网络备案 = env.BEIAN || `&copy; 2025 Check Socks5/HTTP - 基于 Cloudflare Workers 构建的高性能代理验证服务 | by cmliu`;
        let img = 'background: #ffffff;';
        if (env.IMG) {
            const imgs = await 整理(env.IMG);
            img = `background-image: url('${imgs[Math.floor(Math.random() * imgs.length)]}');`;
        }
        return await HTML(网站图标, 网络备案, img);
    }
}


export default {
    /**
     * 主入口 fetch 函数，现在包含了密码验证逻辑
     * @param {Request} request
     * @param {object} env
     * @returns {Promise<Response>}
     */
    async fetch(request, env) {
        // 如果没有设置 PASSWORD 环境变量，则直接跳过验证
        if (!env.PASSWORD) {
            return await handleApplication(request, env);
        }

        const validCookie = await sha256(env.PASSWORD);

        // 处理密码提交
        if (request.method === 'POST') {
            const formData = await request.formData();
            const password = formData.get('password');
            if (password === env.PASSWORD) {
                const response = new Response(null, {
                    status: 302,
                    headers: {
                        'Location': new URL(request.url).pathname, // 重定向回当前页面
                    },
                });
                // 设置安全的HttpOnly Cookie，有效期为1天
                response.headers.append('Set-Cookie', `${AUTH_COOKIE_NAME}=${validCookie}; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax; Secure;`);
                return response;
            } else {
                return createLoginPage(true); // 显示带错误信息的登录页
            }
        }

        // 检查现有Cookie是否有效
        const cookieHeader = request.headers.get('Cookie');
        if (cookieHeader && cookieHeader.includes(`${AUTH_COOKIE_NAME}=${validCookie}`)) {
            // Cookie有效，执行主应用逻辑
            return await handleApplication(request, env);
        }

        // Cookie无效或不存在，显示登录页面
        return createLoginPage();
    },
};



// =========================================================================================
// --- 以下是您原来的所有函数，保持原样，无需任何修改 ---
// =========================================================================================

async function 检测HTTP代理(代理参数) {
    代理参数 = 代理参数.includes("://") ? 代理参数.split('://')[1] : 代理参数;
    console.log("http://", 代理参数);
    try {
        parsedSocks5Address = socks5AddressParser(代理参数);
    } catch (err) {
        let e = err;
        console.log(e.toString());
        return new Response(JSON.stringify({
            success: false,
            error: e.toString(),
            proxy: "http://" + 代理参数
        }, null, 2), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    try {
        const result = await checkHttpProxy('check.socks5.090227.xyz', 80, '/cdn-cgi/trace');
        const 代理落地IP = result.match(/ip=(.*)/)[1];

        // 直接调用IP查询逻辑，而不是发送HTTP请求
        const ipInfo = await getIpInfo(代理落地IP);

        // 返回数据给客户端，并添加CORS头
        return new Response(JSON.stringify({
            success: true,
            proxy: "http://" + 代理参数,
            ...ipInfo
        }, null, 4), {
            headers: {
                "content-type": "application/json; charset=UTF-8",
                'Access-Control-Allow-Origin': '*'
            }
        });
    } catch (error) {
        return new Response(JSON.stringify({
            success: false,
            error: error.message,
            proxy: "http://" + 代理参数
        }, null, 2), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

async function 检测SOCKS5代理(代理参数) {
    代理参数 = 代理参数.includes("://") ? 代理参数.split('://')[1] : 代理参数;
    console.log("socks5://", 代理参数);
    try {
        parsedSocks5Address = socks5AddressParser(代理参数);
    } catch (err) {
        let e = err;
        console.log(e.toString());
        return new Response(JSON.stringify({
            success: false,
            error: e.toString(),
            proxy: "socks5://" + 代理参数
        }, null, 2), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    try {
        const result = await checkSocks5Proxy('check.socks5.090227.xyz', 80, '/cdn-cgi/trace');
        const 代理落地IP = result.match(/ip=(.*)/)[1];

        // 直接调用IP查询逻辑，而不是发送HTTP请求
        const ipInfo = await getIpInfo(代理落地IP);

        // 返回数据给客户端，并添加CORS头
        return new Response(JSON.stringify({
            success: true,
            proxy: "socks5://" + 代理参数,
            ...ipInfo
        }, null, 4), {
            headers: {
                "content-type": "application/json; charset=UTF-8",
                'Access-Control-Allow-Origin': '*'
            }
        });

    } catch (error) {
        return new Response(JSON.stringify({
            success: false,
            error: error.message,
            proxy: "socks5://" + 代理参数
        }, null, 2), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

/**
 * 检测HTTP代理并发送HTTP请求
 * @param {string} hostname 目标主机名
 * @param {number} port 目标端口
 * @param {string} path HTTP请求路径
 */
async function checkHttpProxy(hostname, port, path) {
    const tcpSocket = await httpConnect(hostname, port);

    if (!tcpSocket) {
        throw new Error('HTTP代理连接失败');
    }

    try {
        // 发送HTTP请求
        const httpRequest = `GET ${path} HTTP/1.1\r\nHost: ${hostname}\r\nConnection: close\r\n\r\n`;
        const writer = tcpSocket.writable.getWriter();
        const encoder = new TextEncoder();

        await writer.write(encoder.encode(httpRequest));
        console.log('已发送HTTP请求');

        writer.releaseLock();

        // 读取HTTP响应
        const reader = tcpSocket.readable.getReader();
        const decoder = new TextDecoder();
        let response = '';

        try {
            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                response += decoder.decode(value, { stream: true });
            }
        } finally {
            reader.releaseLock();
        }

        // 关闭连接
        await tcpSocket.close();

        return response;
    } catch (error) {
        // 确保连接被关闭
        try {
            await tcpSocket.close();
        } catch (closeError) {
            console.log('关闭连接时出错:', closeError);
        }
        throw error;
    }
}

/**
 * 检测SOCKS5代理并发送HTTP请求
 * @param {string} hostname 目标主机名
 * @param {number} port 目标端口
 * @param {string} path HTTP请求路径
 */
async function checkSocks5Proxy(hostname, port, path) {
    const tcpSocket = await socks5Connect(3, hostname, port); // 使用域名类型

    if (!tcpSocket) {
        throw new Error('SOCKS5连接失败');
    }

    try {
        // 发送HTTP请求
        const httpRequest = `GET ${path} HTTP/1.1\r\nHost: ${hostname}\r\nConnection: close\r\n\r\n`;
        const writer = tcpSocket.writable.getWriter();
        const encoder = new TextEncoder();

        await writer.write(encoder.encode(httpRequest));
        console.log('已发送HTTP请求');

        writer.releaseLock();

        // 读取HTTP响应
        const reader = tcpSocket.readable.getReader();
        const decoder = new TextDecoder();
        let response = '';

        try {
            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                response += decoder.decode(value, { stream: true });
            }
        } finally {
            reader.releaseLock();
        }

        // 关闭连接
        await tcpSocket.close();

        return response;
    } catch (error) {
        // 确保连接被关闭
        try {
            await tcpSocket.close();
        } catch (closeError) {
            console.log('关闭连接时出错:', closeError);
        }
        throw error;
    }
}

function socks5AddressParser(address) {
    // 使用 "@" 分割地址，分为认证部分和服务器地址部分
    const lastAtIndex = address.lastIndexOf("@");
    let [latter, former] = lastAtIndex === -1 ? [address, undefined] : [address.substring(lastAtIndex + 1), address.substring(0, lastAtIndex)];
    let username, password, hostname, port;

    // 如果存在 former 部分，说明提供了认证信息
    if (former) {
        const formers = former.split(":");
        if (formers.length !== 2) {
            throw new Error('无效的 SOCKS 地址格式：认证部分必须是 "username:password" 的形式');
        }
        [username, password] = formers;
    }

    // 解析服务器地址部分
    const latters = latter.split(":");
    // 检查是否是IPv6地址带端口格式 [xxx]:port
    if (latter.startsWith('[') && latter.includes(']:')) {
		const portIndex = latter.lastIndexOf(']:');
        hostname = latter.substring(0, portIndex + 1);
		port = Number(latter.substring(portIndex + 2));
    } else if (latters.length >= 2) {
        // IPv4地址带端口或域名带端口
        port = Number(latters.pop());
        hostname = latters.join(":");
    } else {
        throw new Error('无效的 SOCKS 地址格式：缺少端口号');
    }
    
    if (isNaN(port) || port <= 0 || port > 65535) {
        throw new Error('无效的 SOCKS 地址格式：端口号无效');
    }

    // 返回解析后的结果
    return {
        username,
        password,
        hostname,
        port,
    }
}

/**
 * 建立 SOCKS5 代理连接
 * @param {number} addressType 目标地址类型（1: IPv4, 3: 域名, 4: IPv6）
 * @param {string} addressRemote 目标地址（可以是 IP 或域名）
 * @param {number} portRemote 目标端口
 */
async function socks5Connect(addressType, addressRemote, portRemote) {
    const { username, password, hostname, port } = parsedSocks5Address;

    let socket;
    try {
        // 连接到 SOCKS5 代理服务器
        socket = connect({
            hostname,
            port,
        });

        const writer = socket.writable.getWriter();
        const reader = socket.readable.getReader();
        const encoder = new TextEncoder();

        // 步骤1: 发送问候消息
        // 0x05: SOCKS5, 0x02: 2种认证方法, 0x00: 无认证, 0x02: 用户名/密码
        const socksGreeting = new Uint8Array([5, 2, 0, 2]);
        await writer.write(socksGreeting);
        console.log('已发送 SOCKS5 问候消息');

        // 步骤2: 接收服务器选择的认证方法
        let res = (await reader.read()).value;
        if (!res || res[0] !== 0x05) {
            throw new Error(`SOCKS5 服务器版本错误: 收到 ${res ? res[0] : '空响应'}，期望是 5`);
        }
        if (res[1] === 0xff) {
            throw new Error("服务器不接受任何认证方法");
        }

        // 步骤3: 如果需要，进行认证
        if (res[1] === 0x02) {
            console.log("SOCKS5 服务器需要认证");
            if (!username || !password) {
                throw new Error("代理需要用户名和密码，但未提供");
            }
            const authRequest = new Uint8Array([
                1,
                username.length,
                ...encoder.encode(username),
                password.length,
                ...encoder.encode(password)
            ]);
            await writer.write(authRequest);
            res = (await reader.read()).value;
            if (!res || res[0] !== 0x01 || res[1] !== 0x00) {
                throw new Error("SOCKS5 服务器认证失败");
            }
        }

        // 步骤4: 发送连接请求
        let DSTADDR;
        const addressRemoteBytes = encoder.encode(addressRemote);
        DSTADDR = new Uint8Array([3, addressRemoteBytes.length, ...addressRemoteBytes]);
        
        const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 0xff]);
        await writer.write(socksRequest);
        console.log('已发送 SOCKS5 请求');

        // 步骤5: 接收连接响应
        res = (await reader.read()).value;
        if (!res || res[1] !== 0x00) {
            throw new Error(`SOCKS5 连接建立失败，错误代码: ${res ? res[1] : '空响应'}`);
        }

        console.log("SOCKS5 连接已建立");

        writer.releaseLock();
        reader.releaseLock();

        return socket;
    } catch (error) {
        if (socket) {
            try {
                await socket.close();
            } catch (closeError) {
                console.log('关闭失败的连接时出错:', closeError);
            }
        }
        throw error;
    }
}

/**
 * 获取IP信息的通用函数
 * @param {string} ip IP地址或域名
 * @returns {Promise<Object>} IP信息对象
 */
async function getIpInfo(ip) {
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const ipv6Regex = /(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/;

    let finalIp = ip;
    let allIps = null; 

    if (!ipv4Regex.test(ip) && !ipv6Regex.test(ip)) {
        try {
            console.log(`正在解析域名: ${ip}`);
            const [ipv4Records, ipv6Records] = await Promise.all([
                fetchDNSRecords(ip, 'A').catch(() => []),
                fetchDNSRecords(ip, 'AAAA').catch(() => [])
            ]);
            const ipv4Addresses = ipv4Records.map(record => record.data).filter(Boolean);
            const ipv6Addresses = ipv6Records.map(record => record.data).filter(Boolean);
            allIps = [...ipv4Addresses, ...ipv6Addresses];
            if (allIps.length === 0) {
                throw new Error(`无法解析域名 ${ip} 的 IP 地址`);
            }
            finalIp = allIps[Math.floor(Math.random() * allIps.length)];
            console.log(`域名 ${ip} 解析为: ${finalIp}`);
        } catch (dnsError) {
            console.error(`DNS 解析失败:`, dnsError);
            throw new Error(`无法解析域名 ${ip}: ${dnsError.message}`);
        }
    } else {
        console.log(`识别为有效IP地址: ${ip}`);
    }

    const response = await fetch(`https://api.ipapi.is/?q=${finalIp}`);
    if (!response.ok) {
        throw new Error(`HTTP error: ${response.status}`);
    }
    const data = await response.json();
    data.timestamp = new Date().toISOString();

    if (finalIp !== ip && allIps) {
        data.domain = ip;
        data.resolved_ip = finalIp;
        data.ips = allIps;
        const ipv4Count = allIps.filter(addr => ipv4Regex.test(addr)).length;
        const ipv6Count = allIps.filter(addr => ipv6Regex.test(addr)).length;
        data.dns_info = {
            total_ips: allIps.length,
            ipv4_count: ipv4Count,
            ipv6_count: ipv6Count,
            selected_ip: finalIp,
            all_ips: allIps
        };
    }

    return data;
}

/**
 * 建立 HTTP 代理连接
 * @param {string} addressRemote 目标地址（可以是 IP 或域名）
 * @param {number} portRemote 目标端口
 */
async function httpConnect(addressRemote, portRemote) {
    const { username, password, hostname, port } = parsedSocks5Address;
    const sock = await connect({
        hostname: hostname,
        port: port
    });

    let connectRequest = `CONNECT ${addressRemote}:${portRemote} HTTP/1.1\r\n`;
    connectRequest += `Host: ${addressRemote}:${portRemote}\r\n`;

    if (username && password) {
        const authString = `${username}:${password}`;
        const base64Auth = btoa(authString);
        connectRequest += `Proxy-Authorization: Basic ${base64Auth}\r\n`;
    }

    connectRequest += `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n`;
    connectRequest += `Proxy-Connection: Keep-Alive\r\n`;
    connectRequest += `Connection: Keep-Alive\r\n`;
    connectRequest += `\r\n`;

    console.log(`正在连接到 ${addressRemote}:${portRemote} 通过代理 ${hostname}:${port}`);

    try {
        const writer = sock.writable.getWriter();
        await writer.write(new TextEncoder().encode(connectRequest));
        writer.releaseLock();
    } catch (err) {
        console.error('发送HTTP CONNECT请求失败:', err);
        throw new Error(`发送HTTP CONNECT请求失败: ${err.message}`);
    }

    const reader = sock.readable.getReader();
    let connected = false;
    let responseBuffer = new Uint8Array(0);

    try {
        while (true) {
            const { value, done } = await reader.read();
            if (done) {
                throw new Error('HTTP代理连接在读取响应时中断');
            }

            const newBuffer = new Uint8Array(responseBuffer.length + value.length);
            newBuffer.set(responseBuffer);
            newBuffer.set(value, responseBuffer.length);
            responseBuffer = newBuffer;

            const respText = new TextDecoder().decode(responseBuffer);
            const headersEndIndex = respText.indexOf('\r\n\r\n');

            if (headersEndIndex !== -1) {
                const headers = respText.substring(0, headersEndIndex);
                console.log(`收到HTTP代理响应: ${headers.split('\r\n')[0]}`);

                if (headers.startsWith('HTTP/1.1 200') || headers.startsWith('HTTP/1.0 200')) {
                    connected = true;
                } else {
                    const errorMsg = `HTTP代理连接失败: ${headers.split('\r\n')[0]}`;
                    throw new Error(errorMsg);
                }
                break;
            }
        }
    } catch (err) {
        reader.releaseLock();
        await sock.close();
        throw new Error(`处理HTTP代理响应失败: ${err.message}`);
    }

    reader.releaseLock();

    if (!connected) {
        await sock.close();
        throw new Error('HTTP代理连接失败: 未收到成功响应');
    }

    console.log(`HTTP代理连接成功: ${addressRemote}:${portRemote}`);
    return sock;
}

async function nginx() {
    const text = `
	<!DOCTYPE html>
	<html>
	<head>
	<title>Welcome to nginx!</title>
	<style>
		body {
			width: 35em;
			margin: 0 auto;
			font-family: Tahoma, Verdana, Arial, sans-serif;
		}
	</style>
	</head>
	<body>
	<h1>Welcome to nginx!</h1>
	<p>If you see this page, the nginx web server is successfully installed and
	working. Further configuration is required.</p>
	
	<p>For online documentation and support please refer to
	<a href="http://nginx.org/">nginx.org</a>.<br/>
	Commercial support is available at
	<a href="http://nginx.com/">nginx.com</a>.</p>
	
	<p><em>Thank you for using nginx.</em></p>
	</body>
	</html>
	`
    return text;
}

async function 代理URL(代理网址, 目标网址) {
    const 网址列表 = await 整理(代理网址);
    const 完整网址 = 网址列表[Math.floor(Math.random() * 网址列表.length)];
    const 解析后的网址 = new URL(完整网址);
    const 协议 = 解析后的网址.protocol.slice(0, -1) || 'https';
    const 主机名 = 解析后的网址.hostname;
    let 路径名 = 解析后的网址.pathname;
    const 查询参数 = 解析后的网址.search;

    if (路径名.charAt(路径名.length - 1) == '/') {
        路径名 = 路径名.slice(0, -1);
    }
    路径名 += 目标网址.pathname;

    const 新网址 = `${协议}://${主机名}${路径名}${查询参数}`;
    const 响应 = await fetch(新网址);
    let 新响应 = new Response(响应.body, {
        status: 响应.status,
        statusText: 响应.statusText,
        headers: 响应.headers
    });
    新响应.headers.set('X-New-URL', 新网址);
    return 新响应;
}

async function 双重哈希(文本) {
    const 编码器 = new TextEncoder();
    const 第一次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(文本));
    const 第一次哈希数组 = Array.from(new Uint8Array(第一次哈希));
    const 第一次十六进制 = 第一次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('');

    const 第二次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(第一次十六进制.slice(7, 27)));
    const 第二次哈希数组 = Array.from(new Uint8Array(第二次哈希));
    const 第二次十六进制 = 第二次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('');

    return 第二次十六进制.toLowerCase();
}

async function 整理(内容) {
    var 替换后的内容 = 内容.replace(/[	|"'\r\n]+/g, ',').replace(/,+/g, ',');
    if (替换后的内容.charAt(0) == ',') 替换后的内容 = 替换后的内容.slice(1);
    if (替换后的内容.charAt(替换后的内容.length - 1) == ',') 替换后的内容 = 替换后的内容.slice(0, 替换后的内容.length - 1);
    return 替换后的内容.split(',');
}

async function fetchDNSRecords(domain, type) {
    const query = new URLSearchParams({ name: domain, type: type });
    const url = `https://cloudflare-dns.com/dns-query?${query.toString()}`;
    const response = await fetch(url, {
        method: 'GET',
        headers: { 'Accept': 'application/dns-json' }
    });
    if (!response.ok) {
        throw new Error(`获取DNS记录失败: ${response.statusText}`);
    }
    const data = await response.json();
    return data.Answer || [];
}

async function HTML(网站图标, 网络备案, img) {
    const html = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Check Socks5/HTTP</title>
    ${网站图标}
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; ${img} background-size: cover; background-position: center; background-attachment: fixed; background-repeat: no-repeat; position: relative; min-height: 100vh; padding: 20px; }
        body::before { content: ''; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(255, 255, 255, 0.1); backdrop-filter: blur(2px); -webkit-backdrop-filter: blur(2px); z-index: 0; pointer-events: none; }
        .container { max-width: 1200px; margin: 0 auto; background: rgba(255, 255, 255, 0.15); backdrop-filter: blur(25px) saturate(180%); -webkit-backdrop-filter: blur(25px) saturate(180%); border-radius: 20px; box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1), 0 10px 20px rgba(0, 0, 0, 0.05), inset 0 1px 0 rgba(255, 255, 255, 0.4), inset 0 -1px 0 rgba(255, 255, 255, 0.1); overflow: hidden; border: 1px solid rgba(255, 255, 255, 0.3); position: relative; z-index: 1; }
        .container::before { content: ''; position: absolute; top: 0; left: 0; right: 0; bottom: 0; background: linear-gradient(135deg, rgba(255, 255, 255, 0.15) 0%, rgba(255, 255, 255, 0.08) 30%, rgba(255, 255, 255, 0.03) 70%, rgba(255, 255, 255, 0.01) 100%); pointer-events: none; z-index: 1; }
        .container::after { content: ''; position: absolute; top: -2px; left: -2px; right: -2px; bottom: -2px; background: rgba(200, 200, 200, 0.2); border-radius: 22px; z-index: -1; filter: blur(4px); opacity: 0.3; }
        .container > * { position: relative; z-index: 2; }
        .header { background: linear-gradient(45deg, #2e7d32, #4caf50); backdrop-filter: blur(15px); -webkit-backdrop-filter: blur(15px); color: #fff; padding: 25px 35px; position: relative; border-bottom: 1px solid rgba(255, 255, 255, 0.2); display: flex; align-items: center; justify-content: space-between; gap: 30px; }
        .header::before { content: ''; position: absolute; top: 0; left: 0; right: 0; bottom: 0; background: linear-gradient(45deg, rgba(46, 125, 50, 0.3), rgba(76, 175, 80, 0.2), rgba(102, 187, 106, 0.3)); pointer-events: none; }
        .header-content { position: relative; z-index: 1; flex-shrink: 0; }
        .header h1 { font-size: 1.8em; margin: 0 0 8px 0; text-shadow: 2px 2px 6px rgba(0,0,0,0.3); }
        .header p { font-size: 0.95em; opacity: 0.95; margin: 0; text-shadow: 1px 1px 3px rgba(0,0,0,0.2); }
        .header-input { position: relative; z-index: 1; flex: 1; max-width: 600px; display: flex; gap: 15px; align-items: center; }
        .header-input input { flex: 1; padding: 14px 20px; border: 2px solid rgba(255, 255, 255, 0.3); border-radius: 12px; font-size: 15px; transition: all 0.3s ease; background: rgba(255, 255, 255, 0.95); color: #333333; box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1); }
        .header-input input:focus { outline: none; border-color: rgba(255, 255, 255, 0.8); box-shadow: 0 0 0 3px rgba(255, 255, 255, 0.2), 0 2px 8px rgba(0, 0, 0, 0.15); background: #ffffff; }
        .header-input input::placeholder { color: #888888; }
        .header-input button { padding: 14px 28px; background: rgba(255, 255, 255, 0.2); backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px); color: white; border: 2px solid rgba(255, 255, 255, 0.3); border-radius: 12px; font-size: 15px; font-weight: 600; cursor: pointer; transition: all 0.3s ease; box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1); text-shadow: 1px 1px 2px rgba(0,0,0,0.2); position: relative; overflow: hidden; white-space: nowrap; }
        .header-input button::before { content: ''; position: absolute; top: 0; left: -100%; width: 100%; height: 100%; background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent); transition: left 0.5s ease; }
        .header-input button:hover::before { left: 100%; }
        .header-input button:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2); background: rgba(255, 255, 255, 0.3); border-color: rgba(255, 255, 255, 0.5); }
        .header-input button:active { transform: translateY(0); box-shadow: 0 2px 6px rgba(0, 0, 0, 0.1); }
        .header-input button:disabled { opacity: 0.6; cursor: not-allowed; transform: none; box-shadow: 0 2px 6px rgba(0, 0, 0, 0.1); background: rgba(150, 150, 150, 0.3); border-color: rgba(150, 150, 150, 0.3); }
        .header-input button:disabled::before { display: none; }
        .input-section { display: none; }
        .results-section { padding: 35px; display: grid; grid-template-columns: 1fr 1fr; gap: 30px; background: rgba(255, 255, 255, 0.15); backdrop-filter: blur(15px); -webkit-backdrop-filter: blur(15px); }
        .info-card { background: rgba(255, 255, 255, 0.25); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); border: 2px solid rgba(255, 255, 255, 0.3); border-radius: 16px; overflow: hidden; box-shadow: 0 6px 20px rgba(0, 0, 0, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.4); transition: all 0.3s ease; }
        .info-card:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15), inset 0 1px 0 rgba(255, 255, 255, 0.5); background: rgba(255, 255, 255, 0.3); }
        .info-card h3 { background: linear-gradient(45deg, #2e7d32, #4caf50); color: white; padding: 22px; margin: 0; font-size: 1.3em; text-align: center; font-weight: 600; text-shadow: 1px 1px 2px rgba(0,0,0,0.2); border-bottom: 1px solid rgba(255, 255, 255, 0.2); }
        .info-content { padding: 28px; background: #ffffff; border-top: 1px solid rgba(200, 200, 200, 0.3); }
        .info-item { display: flex; justify-content: space-between; align-items: center; padding: 14px 0; border-bottom: 1px solid rgba(200, 200, 200, 0.3); }
        .info-item:last-child { border-bottom: none; }
        .info-label { font-weight: 600; color: #333333; min-width: 120px; }
        .info-value { text-align: right; flex: 1; color: #666666; word-break: break-all; }
        .ip-selector { display: flex; align-items: center; justify-content: flex-end; gap: 8px; }
        .more-ip-btn { background: rgba(76, 175, 80, 0.1); color: #2e7d32; border: 1px solid rgba(76, 175, 80, 0.3); border-radius: 4px; padding: 2px 8px; font-size: 0.8em; cursor: pointer; transition: all 0.3s ease; order: 1; }
        .more-ip-btn:hover { background: rgba(76, 175, 80, 0.2); border-color: rgba(76, 175, 80, 0.5); }
        .ip-text { order: 2; }
        .ip-dropdown { position: absolute; right: 0; top: 100%; background: white; border: 1px solid rgba(200, 200, 200, 0.5); border-radius: 8px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15); z-index: 1000; min-width: 200px; max-height: 200px; overflow-y: auto; display: none; }
        .ip-dropdown.show { display: block; }
        .ip-option { padding: 8px 12px; cursor: pointer; transition: background 0.2s ease; border-bottom: 1px solid rgba(200, 200, 200, 0.3); font-size: 0.9em; }
        .ip-option:last-child { border-bottom: none; }
        .ip-option:hover { background: rgba(76, 175, 80, 0.1); }
        .ip-option.active { background: rgba(76, 175, 80, 0.2); color: #2e7d32; font-weight: 600; }
        .ip-value-container { position: relative; }
        .status-yes { background: rgba(211, 47, 47, 0.8); color: white; padding: 5px 10px; border-radius: 8px; font-size: 0.9em; font-weight: 500; }
        .status-no { background: rgba(54,137,61, 0.8); color: white; padding: 5px 10px; border-radius: 8px; font-size: 0.9em; font-weight: 500; }
        .loading, .error, .waiting { text-align: center; padding: 45px; font-size: 1.1em; }
        .loading { color: #666666; }
        .error { color: rgba(211, 47, 47, 0.9); background: rgba(244, 67, 54, 0.1); border-radius: 8px; margin: 10px; border: 1px solid rgba(244, 67, 54, 0.2); }
        .waiting { color: #666666; }
        .spinner { border: 3px solid rgba(200, 200, 200, 0.4); border-top: 3px solid rgba(100, 100, 100, 0.8); border-radius: 50%; width: 32px; height: 32px; animation: spin 1s linear infinite; margin: 0 auto 18px; }
        .github-corner svg { fill: #53b156; color: #ffffff; position: fixed; top: 0; right: 0; border: 0; width: 80px; height: 80px; z-index: 9999; }
        .github-corner:hover .octo-arm { animation: octocat-wave 560ms ease-in-out; }
        @keyframes octocat-wave { 0%, 100% { transform: rotate(0); } 20%, 60% { transform: rotate(-25deg); } 40%, 80% { transform: rotate(10deg); } }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .footer { text-align: center; padding: 25px; color: #666666; font-size: 14px; border-top: 1px solid rgba(255, 255, 255, 0.3); background: rgba(255, 255, 255, 0.2); backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px); }
        @media (max-width: 768px) {
            body { padding: 10px; }
            .header { flex-direction: column; align-items: stretch; gap: 20px; padding: 25px; }
            .header-content { text-align: center; }
            .header h1 { font-size: 1.6em; }
            .header p { font-size: 0.9em; }
            .header-input { flex-direction: column; gap: 15px; max-width: none; }
            .header-input input, .header-input button { width: 100%; }
            .results-section { grid-template-columns: 1fr; padding: 25px; }
            .container { margin: 0; border-radius: 16px; }
            .github-corner:hover .octo-arm { animation: none; }
            .github-corner .octo-arm { animation: octocat-wave 560ms ease-in-out; }
        }
    </style>
</head>
<body>
  <a href="https://github.com/cmliu/CF-Workers-CheckSocks5" target="_blank" class="github-corner" aria-label="View source on Github">
    <svg viewBox="0 0 250 250" aria-hidden="true"><path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path><path d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2" fill="currentColor" style="transform-origin: 130px 106px;" class="octo-arm"></path><path d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z" fill="currentColor" class="octo-body"></path></svg>
  </a>
    <div class="container">
        <div class="header">
            <div class="header-content">
                <h1>代理检测工具</h1>
                <p>检测代理服务器的出入口信息，支持 SOCKS5 和 HTTP 代理</p>
            </div>
            <div class="header-input">
                <input type="text" id="proxyInput" placeholder="输入代理链接，例如：socks5://user:pass@host:port" />
                <button id="checkBtn" onclick="checkProxy()">检查代理</button>
            </div>
        </div>
        <div class="results-section">
            <div class="info-card">
                <h3>入口信息</h3>
                <div class="info-content" id="entryInfo"><div class="waiting">请输入代理链接并点击检查</div></div>
            </div>
            <div class="info-card">
                <h3>出口信息</h3>
                <div class="info-content" id="exitInfo"><div class="waiting">请输入代理链接并点击检查</div></div>
            </div>
        </div>
        <div class="footer">${网络备案}</div>
    </div>
    <script>
        let currentDomainInfo = null, currentProxyTemplate = null;
        function preprocessProxyUrl(input) { let processed = input.trim(); if (processed.includes('#')) { processed = processed.split('#')[0].trim(); } while (processed.startsWith('/')) { processed = processed.substring(1); } if (!processed.includes('://')) { processed = 'socks5://' + processed; } const urlPart = processed.includes('://') ? processed.split('://')[1] : processed; let processedUrlPart = urlPart; let authPart = ''; if (processedUrlPart.includes('@')) { const lastAtIndex = processedUrlPart.lastIndexOf('@'); authPart = processedUrlPart.substring(0, lastAtIndex + 1); processedUrlPart = processedUrlPart.substring(lastAtIndex + 1); } if (processedUrlPart.startsWith('[') && processedUrlPart.includes(']:')) { return processed; } const parts = processedUrlPart.split(':'); if (parts.length > 2) { const port = parts[parts.length - 1]; const hostPart = parts.slice(0, -1).join(':'); if (isIPv6Address(hostPart)) { const protocol = processed.includes('://') ? processed.split('://')[0] : 'socks5'; processed = protocol + '://' + authPart + '[' + hostPart + ']:' + port; } } return processed; }
        function extractHostFromProxy(proxyUrl) { try { let urlPart = proxyUrl.includes('://') ? proxyUrl.split('://')[1] : proxyUrl; if (urlPart.includes('@')) { const lastAtIndex = urlPart.lastIndexOf('@'); urlPart = urlPart.substring(lastAtIndex + 1); } if (urlPart.startsWith('[') && urlPart.includes(']:')) { return urlPart.substring(1, urlPart.indexOf(']:')); } return urlPart.split(':')[0]; } catch (error) { throw new Error('无法解析代理链接格式'); } }
        function isIPAddress(host) { const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/; const ipv6Regex = /(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/; return ipv4Regex.test(host) || ipv6Regex.test(host); }
        function isIPv6Address(host) { const ipv6Regex = /(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/; return ipv6Regex.test(host); }
        function replaceHostInProxy(proxyUrl, newHost) { try { const [protocol, rest] = proxyUrl.split('://'); let urlPart = rest, authPart = ''; if (urlPart.includes('@')) { const lastAtIndex = urlPart.lastIndexOf('@'); authPart = urlPart.substring(0, lastAtIndex + 1); urlPart = urlPart.substring(lastAtIndex + 1); } let port; let processedNewHost = newHost; if (isIPv6Address(newHost) && !newHost.startsWith('[')) { processedNewHost = '[' + newHost + ']'; } if (urlPart.startsWith('[') && urlPart.includes(']:')) { const portIndex = urlPart.lastIndexOf(']:'); port = urlPart.substring(portIndex + 2); } else { const parts = urlPart.split(':'); port = parts[parts.length - 1]; } return protocol + '://' + authPart + processedNewHost + ':' + port; } catch (error) { throw new Error('无法替换代理链接中的主机'); } }
        async function fetchDNSRecords(domain, type) { const query = new URLSearchParams({ name: domain, type: type }); const url = \`https://cloudflare-dns.com/dns-query?\${query.toString()}\`; const response = await fetch(url, { method: 'GET', headers: { 'Accept': 'application/dns-json' } }); if (!response.ok) { throw new Error(\`获取DNS记录失败: \${response.statusText}\`); } const data = await response.json(); return data.Answer || []; }
        async function resolveDomainIPs(domain) { try { const [ipv4Records, ipv6Records] = await Promise.all([ fetchDNSRecords(domain, 'A').catch(() => []), fetchDNSRecords(domain, 'AAAA').catch(() => []) ]); const ipv4Addresses = ipv4Records.map(record => record.data).filter(Boolean); const ipv6Addresses = ipv6Records.map(record => record.data).filter(Boolean); const allIPs = [...ipv4Addresses, ...ipv6Addresses]; if (allIPs.length === 0) { throw new Error(\`无法解析域名 \${domain} 的 IP 地址\`); } return { domain: domain, all_ips: allIPs, default_ip: allIPs[0] }; } catch (error) { throw new Error(\`DNS解析失败: \${error.message}\`); } }
        function getAbusescoreColor(score) { const match = (score || '0').match(/([0-9.]+)/); if (!match) return '#28a745'; const percentage = parseFloat(match[1]) * 100; const red = Math.min(255, Math.round(percentage * 2.55)); const green = Math.min(255, Math.round((100 - percentage) * 2.55)); return \`rgb(\${red}, \${green}, 0)\`; }
        function formatInfoDisplay(data, containerId, showIPSelector = false) { const container = document.getElementById(containerId); if (!data) { container.innerHTML = '<div class="error">数据为空，无法渲染</div>'; return; } if (data.error) { container.innerHTML = \`<div class="error">获取信息失败: \${data.error}</div>\`; return; } const abusescoreColor = getAbusescoreColor(data.asn?.abuser_score); const abusescoreMatch = (data.asn?.abuser_score || '0').match(/([0-9.]+)/); const abusescorePercentage = abusescoreMatch ? (parseFloat(abusescoreMatch[1]) * 100).toFixed(2) + '%' : '0%'; const ipDisplay = showIPSelector && currentDomainInfo && currentDomainInfo.all_ips.length > 1 ? \`<div class="ip-selector"><button class="more-ip-btn" onclick="toggleIPDropdown()">更多IP</button><span class="ip-text">\${data.resolved_ip || data.ip || 'N/A'}</span><div class="ip-dropdown" id="ipDropdown">\${currentDomainInfo.all_ips.map(ip => \`<div class="ip-option \${ip === (data.resolved_ip || data.ip) ? 'active' : ''}" onclick="selectIP('\${ip}')">\${ip}</div>\`).join('')}</div></div>\` : data.resolved_ip || data.ip || 'N/A'; container.innerHTML = \`<div class="info-item"><span class="info-label">IP地址:</span><span class="info-value"><div class="ip-value-container">\${ipDisplay}</div></span></div>\${data.domain ? \`<div class="info-item"><span class="info-label">域名:</span><span class="info-value">\${data.domain}</span></div>\` : ''}<div class="info-item"><span class="info-label">网络爬虫:</span><span class="info-value"><span class="\${data.is_crawler ? 'status-yes' : 'status-no'}">\${data.is_crawler ? '是' : '否'}</span></span></div><div class="info-item"><span class="info-label">数据中心:</span><span class="info-value"><span class="\${data.is_datacenter ? 'status-yes' : 'status-no'}">\${data.is_datacenter ? '是' : '否'}</span></span></div><div class="info-item"><span class="info-label">Tor网络:</span><span class="info-value"><span class="\${data.is_tor ? 'status-yes' : 'status-no'}">\${data.is_tor ? '是' : '否'}</span></span></div><div class="info-item"><span class="info-label">代理:</span><span class="info-value"><span class="\${data.is_proxy ? 'status-yes' : 'status-no'}">\${data.is_proxy ? '是' : '否'}</span></span></div><div class="info-item"><span class="info-label">VPN:</span><span class="info-value"><span class="\${data.is_vpn ? 'status-yes' : 'status-no'}">\${data.is_vpn ? '是' : '否'}</span></span></div><div class="info-item"><span class="info-label">滥用行为:</span><span class="info-value"><span class="\${data.is_abuser ? 'status-yes' : 'status-no'}">\${data.is_abuser ? '是' : '否'}</span></span></div><div class="info-item"><span class="info-label">滥用风险:</span><span class="info-value"><span style="background-color: \${abusescoreColor}; color: white; padding: 4px 8px; border-radius: 5px; font-size: 0.9em;">\${abusescorePercentage}</span></span></div><div class="info-item"><span class="info-label">ASN:</span><span class="info-value">\${'AS' + (data.asn?.asn || 'N/A')}</span></div><div class="info-item"><span class="info-label">组织:</span><span class="info-value">\${data.asn?.org || 'N/A'}</span></div><div class="info-item"><span class="info-label">国家:</span><span class="info-value">\${data.location?.country || 'N/A'} (\${data.location?.country_code || 'N/A'})</span></div><div class="info-item"><span class="info-label">城市:</span><span class="info-value">\${data.location?.city || 'N/A'}</span></div>\`; }
        function toggleIPDropdown() { const dropdown = document.getElementById('ipDropdown'); if (!dropdown) return; const isShown = dropdown.classList.toggle('show'); function closeListener(e) { if (!e.target.closest('.ip-value-container')) { dropdown.classList.remove('show'); document.removeEventListener('click', closeListener); } } if (isShown) { document.addEventListener('click', closeListener); } }
        async function selectIP(selectedIP) { const dropdown = document.getElementById('ipDropdown'); if(dropdown) dropdown.classList.remove('show'); const checkBtn = document.getElementById('checkBtn'); const entryInfo = document.getElementById('entryInfo'); const exitInfo = document.getElementById('exitInfo'); checkBtn.disabled = true; entryInfo.innerHTML = '<div class="loading"><div class="spinner"></div>正在获取入口信息...</div>'; exitInfo.innerHTML = '<div class="loading"><div class="spinner"></div>正在获取出口信息...</div>'; try { let entryQueryIP = selectedIP.startsWith('[') && selectedIP.endsWith(']') ? selectedIP.substring(1, selectedIP.length - 1) : selectedIP; const newProxyUrl = replaceHostInProxy(currentProxyTemplate, selectedIP); const [entryPromise, exitPromise] = await Promise.allSettled([ fetchEntryInfo(entryQueryIP), (async () => { const proxyResponse = await fetch(\`/check?proxy=\${encodeURIComponent(newProxyUrl)}\`); return proxyResponse.json(); })() ]); if (entryPromise.status === 'fulfilled') { formatInfoDisplay(entryPromise.value, 'entryInfo', true); } else { entryInfo.innerHTML = '<div class="error">入口信息获取失败</div>'; } if (exitPromise.status === 'fulfilled' && exitPromise.value.success) { formatInfoDisplay(exitPromise.value, 'exitInfo', false); } else { const errorMsg = exitPromise.value?.error || '请检查代理链接或网络'; exitInfo.innerHTML = \`<div class="error">代理检测失败: \${errorMsg}</div>\`; } } catch (error) { entryInfo.innerHTML = '<div class="error">切换失败</div>'; exitInfo.innerHTML = '<div class="error">切换失败</div>'; } finally { checkBtn.disabled = false; } }
        async function fetchEntryInfo(host, retryCount = 0) { try { const response = await fetch(\`/ip-info?ip=\${encodeURIComponent(host)}&token=${临时TOKEN}\`); if (!response.ok) throw new Error(\`status: \${response.status}\`); return await response.json(); } catch (error) { if (retryCount < 2) { await new Promise(resolve => setTimeout(resolve, 500)); return fetchEntryInfo(host, retryCount + 1); } return { error: error.message }; } }
        async function checkProxy() { const proxyInput = document.getElementById('proxyInput'); const checkBtn = document.getElementById('checkBtn'); const entryInfo = document.getElementById('entryInfo'); const exitInfo = document.getElementById('exitInfo'); const rawProxyUrl = proxyInput.value.trim(); if (!rawProxyUrl) return; const proxyUrl = preprocessProxyUrl(rawProxyUrl); currentProxyTemplate = proxyUrl; proxyInput.value = proxyUrl; checkBtn.disabled = true; entryInfo.innerHTML = '<div class="loading"><div class="spinner"></div>正在解析代理...</div>'; exitInfo.innerHTML = '<div class="loading"><div class="spinner"></div>正在解析代理...</div>'; try { const host = extractHostFromProxy(proxyUrl); let targetIP = host, targetProxyUrl = proxyUrl; currentDomainInfo = null; if (!isIPAddress(host)) { entryInfo.innerHTML = '<div class="loading"><div class="spinner"></div>正在解析域名...</div>'; try { currentDomainInfo = await resolveDomainIPs(host); targetIP = currentDomainInfo.default_ip; targetProxyUrl = replaceHostInProxy(proxyUrl, targetIP); currentProxyTemplate = proxyUrl; } catch (dnsError) { entryInfo.innerHTML = \`<div class="error">域名解析失败: \${dnsError.message}</div>\`; exitInfo.innerHTML = \`<div class="error">域名解析失败</div>\`; checkBtn.disabled = false; return; } } entryInfo.innerHTML = '<div class="loading"><div class="spinner"></div>正在获取入口信息...</div>'; exitInfo.innerHTML = '<div class="loading"><div class="spinner"></div>正在检测代理...</div>'; let entryQueryIP = targetIP.startsWith('[') && targetIP.endsWith(']') ? targetIP.substring(1, targetIP.length - 1) : targetIP; const [entryPromise, exitPromise] = await Promise.allSettled([ fetchEntryInfo(entryQueryIP), (async () => { const proxyResponse = await fetch(\`/check?proxy=\${encodeURIComponent(targetProxyUrl)}\`); return proxyResponse.json(); })() ]); if (entryPromise.status === 'fulfilled') { formatInfoDisplay(entryPromise.value, 'entryInfo', currentDomainInfo && currentDomainInfo.all_ips.length > 1); } else { entryInfo.innerHTML = '<div class="error">入口信息获取失败</div>'; } if (exitPromise.status === 'fulfilled' && exitPromise.value.success) { formatInfoDisplay(exitPromise.value, 'exitInfo', false); } else { const errorMsg = exitPromise.value?.error || '请检查代理链接或网络'; exitInfo.innerHTML = \`<div class="error">代理检测失败: \${errorMsg}</div>\`; } } catch (error) { entryInfo.innerHTML = \`<div class="error">检测失败: \${error.message}</div>\`; exitInfo.innerHTML = '<div class="error">检测失败</div>'; } finally { checkBtn.disabled = false; } }
        document.getElementById('proxyInput').addEventListener('keypress', function(e) { if (e.key === 'Enter') { checkProxy(); } });
    </script>
</body>
</html>
    `;

    return new Response(html, {
        headers: { "content-type": "text/html;charset=UTF-8" }
    });
}
