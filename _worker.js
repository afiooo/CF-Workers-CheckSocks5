import { connect } from 'cloudflare:sockets';
const currentDate = new Date();
currentDate.setHours(0, 0, 0, 0);
let token = Math.ceil(currentDate.getTime() / (1000 * 60 * 13)); // 每13分钟一个时间戳
let parsedSocks5Address = {};
export default {
    async fetch(request, env) {
        const url = new URL(request.url);
        const timestamp = Math.ceil(currentDate.getTime() / (1000 * 60 * 7)); // 每7分钟一个时间戳
        token = env.TOKEN || token;
        if (url.pathname.toLowerCase() === "/check") {
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
        if (env.URL302) return Response.redirect(env.URL302, 302);
        else if (env.URL) {
            if (env.URL.toString().toLowerCase() == 'nginx') {
                return new Response(await nginx(), {
                    headers: {
                        'Content-Type': 'text/html; charset=UTF-8',
                    },
                });
            } else return await 代理URL(env.URL, url);
        } else return await HTML();
    },
};

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
    const tcpSocket = await socks5Connect(2, hostname, port);

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
    // reverse() 是为了处理没有认证信息的情况，确保 latter 总是包含服务器地址
    let [latter, former] = address.split("@").reverse();
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
    // 从末尾提取端口号（因为 IPv6 地址中也包含冒号）
    port = Number(latters.pop());
    if (isNaN(port)) {
        throw new Error('无效的 SOCKS 地址格式：端口号必须是数字');
    }

    // 剩余部分就是主机名（可能是域名、IPv4 或 IPv6 地址）
    hostname = latters.join(":");

    // 处理 IPv6 地址的特殊情况
    // IPv6 地址包含多个冒号，所以必须用方括号括起来，如 [2001:db8::1]
    const regex = /^\[.*\]$/;
    if (hostname.includes(":") && !regex.test(hostname)) {
        throw new Error('无效的 SOCKS 地址格式：IPv6 地址必须用方括号括起来，如 [2001:db8::1]');
    }

    //if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(hostname)) hostname = `${atob('d3d3Lg==')}${hostname}${atob('LmlwLjA5MDIyNy54eXo=')}`;
    // 返回解析后的结果
    return {
        username,  // 用户名，如果没有则为 undefined
        password,  // 密码，如果没有则为 undefined
        hostname,  // 主机名，可以是域名、IPv4 或 IPv6 地址
        port,	 // 端口号，已转换为数字类型
    }
}

/**
 * 建立 SOCKS5 代理连接
 * @param {number} addressType 目标地址类型（1: IPv4, 2: 域名, 3: IPv6）
 * @param {string} addressRemote 目标地址（可以是 IP 或域名）
 * @param {number} portRemote 目标端口
 */
async function socks5Connect(addressType, addressRemote, portRemote) {
    const { username, password, hostname, port } = parsedSocks5Address;

    let socket;
    try {
        // 连接到 SOCKS5 代理服务器
        socket = connect({
            hostname, // SOCKS5 服务器的主机名
            port,     // SOCKS5 服务器的端口
        });

        // 请求头格式（Worker -> SOCKS5 服务器）:
        // +----+----------+----------+
        // |VER | NMETHODS | METHODS  |
        // +----+----------+----------+
        // | 1  |    1     | 1 to 255 |
        // +----+----------+----------+

        // https://en.wikipedia.org/wiki/SOCKS#SOCKS5
        // METHODS 字段的含义:
        // 0x00 不需要认证
        // 0x02 用户名/密码认证 https://datatracker.ietf.org/doc/html/rfc1929
        const socksGreeting = new Uint8Array([5, 2, 0, 2]);
        // 5: SOCKS5 版本号, 2: 支持的认证方法数, 0和2: 两种认证方法（无认证和用户名/密码）

        const writer = socket.writable.getWriter();

        await writer.write(socksGreeting);
        console.log('已发送 SOCKS5 问候消息');

        const reader = socket.readable.getReader();
        const encoder = new TextEncoder();
        let res = (await reader.read()).value;
        // 响应格式（SOCKS5 服务器 -> Worker）:
        // +----+--------+
        // |VER | METHOD |
        // +----+--------+
        // | 1  |   1    |
        // +----+--------+
        if (res[0] !== 0x05) {
            console.log(`SOCKS5 服务器版本错误: 收到 ${res[0]}，期望是 5`);
            throw new Error(`SOCKS5 服务器版本错误: 收到 ${res[0]}，期望是 5`);
        }
        if (res[1] === 0xff) {
            console.log("服务器不接受任何认证方法");
            throw new Error("服务器不接受任何认证方法");
        }

        // 如果返回 0x0502，表示需要用户名/密码认证
        if (res[1] === 0x02) {
            console.log("SOCKS5 服务器需要认证");
            if (!username || !password) {
                console.log("请提供用户名和密码");
                throw new Error("请提供用户名和密码");
            }
            // 认证请求格式:
            // +----+------+----------+------+----------+
            // |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
            // +----+------+----------+------+----------+
            // | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
            // +----+------+----------+------+----------+
            const authRequest = new Uint8Array([
                1,                       // 认证子协议版本
                username.length,         // 用户名长度
                ...encoder.encode(username), // 用户名
                password.length,         // 密码长度
                ...encoder.encode(password)  // 密码
            ]);
            await writer.write(authRequest);
            res = (await reader.read()).value;
            // 期望返回 0x0100 表示认证成功
            if (res[0] !== 0x01 || res[1] !== 0x00) {
                console.log("SOCKS5 服务器认证失败");
                throw new Error("SOCKS5 服务器认证失败");
            }
        }

        // 请求数据格式（Worker -> SOCKS5 服务器）:
        // +----+-----+-------+------+----------+----------+
        // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        // +----+-----+-------+------+----------+----------+
        // | 1  |  1  | X'00' |  1   | Variable |    2     |
        // +----+-----+-------+------+----------+----------+
        // ATYP: 地址类型
        // 0x01: IPv4 地址
        // 0x03: 域名
        // 0x04: IPv6 地址
        // DST.ADDR: 目标地址
        // DST.PORT: 目标端口（网络字节序）

        // addressType
        // 1 --> IPv4  地址长度 = 4
        // 2 --> 域名
        // 3 --> IPv6  地址长度 = 16
        let DSTADDR;    // DSTADDR = ATYP + DST.ADDR
        switch (addressType) {
            case 1: // IPv4
                DSTADDR = new Uint8Array(
                    [1, ...addressRemote.split('.').map(Number)]
                );
                break;
            case 2: // 域名
                DSTADDR = new Uint8Array(
                    [3, addressRemote.length, ...encoder.encode(addressRemote)]
                );
                break;
            case 3: // IPv6
                DSTADDR = new Uint8Array(
                    [4, ...addressRemote.split(':').flatMap(x => [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)])]
                );
                break;
            default:
                console.log(`无效的地址类型: ${addressType}`);
                throw new Error(`无效的地址类型: ${addressType}`);
        }
        const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 0xff]);
        // 5: SOCKS5版本, 1: 表示CONNECT请求, 0: 保留字段
        // ...DSTADDR: 目标地址, portRemote >> 8 和 & 0xff: 将端口转为网络字节序
        await writer.write(socksRequest);
        console.log('已发送 SOCKS5 请求');

        res = (await reader.read()).value;
        // 响应格式（SOCKS5 服务器 -> Worker）:
        //  +----+-----+-------+------+----------+----------+
        // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        // +----+-----+-------+------+----------+----------+
        // | 1  |  1  | X'00' |  1   | Variable |    2     |
        // +----+-----+-------+------+----------+----------+
        if (res[1] === 0x00) {
            console.log("SOCKS5 连接已建立");
        } else {
            console.log(`SOCKS5 连接建立失败，错误代码: ${res[1]}`);
            throw new Error(`SOCKS5 连接建立失败，错误代码: ${res[1]}`);
        }

        // 在调用 startTls 之前必须释放 reader 和 writer 的锁
        writer.releaseLock();
        reader.releaseLock();

        return socket;
    } catch (error) {
        // 如果连接建立失败，确保清理资源
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
 * @param {string} ip IP地址
 * @returns {Promise<Object>} IP信息对象
 */
async function getIpInfo(ip) {
    // 使用Worker代理请求HTTP的IP API
    const response = await fetch(`https://api.ipapi.is/?q=${ip}`);

    if (!response.ok) {
        throw new Error(`HTTP error: ${response.status}`);
    }

    const data = await response.json();

    // 添加时间戳到成功的响应数据中
    data.timestamp = new Date().toISOString();

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

    // 构建HTTP CONNECT请求
    let connectRequest = `CONNECT ${addressRemote}:${portRemote} HTTP/1.1\r\n`;
    connectRequest += `Host: ${addressRemote}:${portRemote}\r\n`;

    // 添加代理认证（如果需要）
    if (username && password) {
        const authString = `${username}:${password}`;
        const base64Auth = btoa(authString);
        connectRequest += `Proxy-Authorization: Basic ${base64Auth}\r\n`;
    }

    connectRequest += `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n`;
    connectRequest += `Proxy-Connection: Keep-Alive\r\n`;
    connectRequest += `Connection: Keep-Alive\r\n`; // 添加标准 Connection 头
    connectRequest += `\r\n`;

    console.log(`正在连接到 ${addressRemote}:${portRemote} 通过代理 ${hostname}:${port}`);

    try {
        // 发送连接请求
        const writer = sock.writable.getWriter();
        await writer.write(new TextEncoder().encode(connectRequest));
        writer.releaseLock();
    } catch (err) {
        console.error('发送HTTP CONNECT请求失败:', err);
        throw new Error(`发送HTTP CONNECT请求失败: ${err.message}`);
    }

    // 读取HTTP响应
    const reader = sock.readable.getReader();
    let respText = '';
    let connected = false;
    let responseBuffer = new Uint8Array(0);

    try {
        while (true) {
            const { value, done } = await reader.read();
            if (done) {
                console.error('HTTP代理连接中断');
                throw new Error('HTTP代理连接中断');
            }

            // 合并接收到的数据
            const newBuffer = new Uint8Array(responseBuffer.length + value.length);
            newBuffer.set(responseBuffer);
            newBuffer.set(value, responseBuffer.length);
            responseBuffer = newBuffer;

            // 将收到的数据转换为文本
            respText = new TextDecoder().decode(responseBuffer);

            // 检查是否收到完整的HTTP响应头
            if (respText.includes('\r\n\r\n')) {
                // 分离HTTP头和可能的数据部分
                const headersEndPos = respText.indexOf('\r\n\r\n') + 4;
                const headers = respText.substring(0, headersEndPos);

                console.log(`收到HTTP代理响应: ${headers.split('\r\n')[0]}`);

                // 检查响应状态
                if (headers.startsWith('HTTP/1.1 200') || headers.startsWith('HTTP/1.0 200')) {
                    connected = true;

                    // 如果响应头之后还有数据，我们需要保存这些数据以便后续处理
                    if (headersEndPos < responseBuffer.length) {
                        const remainingData = responseBuffer.slice(headersEndPos);
                        // 创建一个缓冲区来存储这些数据，以便稍后使用
                        const dataStream = new ReadableStream({
                            start(controller) {
                                controller.enqueue(remainingData);
                            }
                        });

                        // 创建一个新的TransformStream来处理额外数据
                        const { readable, writable } = new TransformStream();
                        dataStream.pipeTo(writable).catch(err => console.error('处理剩余数据错误:', err));

                        // 替换原始readable流
                        // @ts-ignore
                        sock.readable = readable;
                    }
                } else {
                    const errorMsg = `HTTP代理连接失败: ${headers.split('\r\n')[0]}`;
                    console.error(errorMsg);
                    throw new Error(errorMsg);
                }
                break;
            }
        }
    } catch (err) {
        reader.releaseLock();
        throw new Error(`处理HTTP代理响应失败: ${err.message}`);
    }

    reader.releaseLock();

    if (!connected) {
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

    // 解析目标 URL
    const 解析后的网址 = new URL(完整网址);
    console.log(解析后的网址);
    // 提取并可能修改 URL 组件
    const 协议 = 解析后的网址.protocol.slice(0, -1) || 'https';
    const 主机名 = 解析后的网址.hostname;
    let 路径名 = 解析后的网址.pathname;
    const 查询参数 = 解析后的网址.search;

    // 处理路径名
    if (路径名.charAt(路径名.length - 1) == '/') {
        路径名 = 路径名.slice(0, -1);
    }
    路径名 += 目标网址.pathname;

    // 构建新的 URL
    const 新网址 = `${协议}://${主机名}${路径名}${查询参数}`;

    // 反向代理请求
    const 响应 = await fetch(新网址);

    // 创建新的响应
    let 新响应 = new Response(响应.body, {
        status: 响应.status,
        statusText: 响应.statusText,
        headers: 响应.headers
    });

    // 添加自定义头部，包含 URL 信息
    //新响应.headers.set('X-Proxied-By', 'Cloudflare Worker');
    //新响应.headers.set('X-Original-URL', 完整网址);
    新响应.headers.set('X-New-URL', 新网址);

    return 新响应;
}

/**
 * 双重MD5哈希函数
 * 这个函数对输入文本进行两次MD5哈希，增强安全性
 * 第二次哈希使用第一次哈希结果的一部分作为输入
 * 
 * @param {string} 文本 要哈希的文本
 * @returns {Promise<string>} 双重哈希后的小写十六进制字符串
 */
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
	// 将制表符、双引号、单引号和换行符都替换为逗号
	// 然后将连续的多个逗号替换为单个逗号
	var 替换后的内容 = 内容.replace(/[	|"'\r\n]+/g, ',').replace(/,+/g, ',');

	// 删除开头和结尾的逗号（如果有的话）
	if (替换后的内容.charAt(0) == ',') 替换后的内容 = 替换后的内容.slice(1);
	if (替换后的内容.charAt(替换后的内容.length - 1) == ',') 替换后的内容 = 替换后的内容.slice(0, 替换后的内容.length - 1);

	// 使用逗号分割字符串，得到地址数组
	const 地址数组 = 替换后的内容.split(',');

	return 地址数组;
}

async function HTML() {
    // 否则返回 HTML 页面
    const html = ``;

    return new Response(html, {
        headers: { "content-type": "text/html;charset=UTF-8" }
    });
}