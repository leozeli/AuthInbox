/*
index.ts
This is the main file for the Auth Inbox Email Worker.
created by: github@TooonyChen
created on: 2024 Oct 07
Last updated: 2024 Oct 07
*/

import indexHtml from './index.html';

export interface Env {
	// If you set another name in wrangler.toml as the value for 'binding',
	// replace "DB" with the variable name you defined.
	DB: D1Database;
	FrontEndAdminID: string;
	FrontEndAdminPassword: string;
	barkTokens: string;
	barkUrl: string;
	GoogleAPIKey: string;
	UseBark: string;
}

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		// 将依赖 env 的常量移到函数内部
		const FrontEndAdminID = env.FrontEndAdminID;
		const FrontEndAdminPassword = env.FrontEndAdminPassword;

		// 提取 Authorization 头
		const authHeader = request.headers.get('Authorization');

		// 如果没有 Authorization 头，提示进行身份验证
		if (!authHeader) {
			return new Response('Unauthorized', {
				status: 401,
				headers: {
					'WWW-Authenticate': 'Basic realm="User Visible Realm"',
				},
			});
		}

		// 检查 Authorization 头是否使用 Basic 认证
		if (!authHeader.startsWith('Basic ')) {
			return new Response('Unauthorized', {
				status: 401,
				headers: {
					'WWW-Authenticate': 'Basic realm="User Visible Realm"',
				},
			});
		}

		// 解码 base64 编码的凭据
		const base64Credentials = authHeader.substring('Basic '.length);
		const decodedCredentials = atob(base64Credentials);

		// 将凭据分割为用户名和密码
		const [username, password] = decodedCredentials.split(':');

		// 验证凭据
		if (
			username !== FrontEndAdminID ||
			password !== FrontEndAdminPassword
		) {
			return new Response('Unauthorized', {
				status: 401,
				headers: {
					'WWW-Authenticate': 'Basic realm="User Visible Realm"',
				},
			});
		}

		try {
			const { results } = await env.DB.prepare(
				'SELECT from_org, to_addr, topic, code, created_at FROM code_mails ORDER BY created_at DESC'
			).all();

			let dataHtml = '';
			for (const row of results) {
				const codeLinkParts = row.code.split(',');
				let codeLinkContent;

				if (codeLinkParts.length > 1) {
					const [code, link] = codeLinkParts;
					codeLinkContent = `${code}<br><a href="${link}" target="_blank">${row.topic}</a>`;
				} else if (row.code.startsWith('http')) {
					codeLinkContent = `<a href="${row.code}" target="_blank">${row.topic}</a>`;
				} else {
					codeLinkContent = row.code;
				}

				dataHtml += `<tr>
                    <td>${row.from_org}</td>
                    <td>${row.to_addr}</td>
                    <td>${row.topic}</td>
                    <td>${codeLinkContent}</td>
                    <td>${row.created_at}</td>
                </tr>`;
			}

			let responseHtml = indexHtml
				.replace('{{TABLE_HEADERS}}', `
                    <tr>
                        <th>From</th>
                        <th>To</th>
                        <th>Topic</th>
                        <th>Code/Link</th>
                        <th>Receive Time (GMT)</th>
                    </tr>
                `)
				.replace('{{DATA}}', dataHtml);

			return new Response(responseHtml, {
				headers: {
					'Content-Type': 'text/html',
				},
			});
		} catch (error) {
			console.error('Error querying database:', error);
			return new Response('Internal Server Error', { status: 500 });
		}
	},

	// 主要功能
	async email(message, env, ctx) {
		const useBark = env.UseBark.toLowerCase() === 'true'; // true or false

		const rawEmail = await new Response(message.raw).text();
		const message_id = message.headers.get("Message-ID");

		// 将电子邮件保存到数据库
		const { success } = await env.DB.prepare(
			`INSERT INTO raw_mails (from_addr, to_addr, raw, message_id) VALUES (?, ?, ?, ?)`
		).bind(
			message.from, message.to, rawEmail, message_id  // 将电子邮件详细信息绑定到 SQL 语句
		).run();

		// 检查电子邮件是否成功保存
		if (!success) {
			message.setReject(`Failed to save message from ${message.from} to ${message.to}`); // 如果保存失败，则拒绝消息
			console.log(`Failed to save message from ${message.from} to ${message.to}`); // 记录保存失败
		}

		// 调用AI，让AI抓取验证码，让AI返回`title`和`code`
		// title: 邮件是哪个公司/组织发来的验证码, 比如'Netflix'
		// code: 验证码/链接/密码，比如'123456'or'https://example.com/verify?code=123456',如都有则返回'code, link'
		// topic: 邮件主题，比如'line register verification'

		try {
			// 添加重试机制
			const maxRetries = 3;
			let retryCount = 0;
			let extractedData = null;
			// extract formatted data
			// Send title and code to Bark using GET request for each token
			if (useBark) {
				const barkUrl = env.barkUrl; // "https://api.day.app"
				// [token1, token2]
				const barkTokens = env.barkTokens
					.replace(/^\[|\]$/g, '')
					.split(',')
					.map(token => token.trim());

				const barkUrlEncodedTitle = encodeURIComponent(title);
				const barkUrlEncodedCode = encodeURIComponent(code);

				for (const token of barkTokens) {
					const barkRequestUrl = `${barkUrl}/${token}/${barkUrlEncodedTitle}/${barkUrlEncodedCode}`;

					const barkResponse = await fetch(barkRequestUrl, {
						method: "GET"
					});

					if (barkResponse.ok) {
						console.log(`Successfully sent notification to Bark for token ${token} for message from ${message.from} to ${message.to}`);
						const responseData = await barkResponse.json();
						console.log("Bark response:", responseData);
					} else {
						console.error(`Failed to send notification to Bark for token ${token}: ${barkResponse.status} ${barkResponse.statusText}`);
					}
				}
			} else {
				console.log("No code found in this email, skipping Bark notification.");
			}
		} catch (e) {
			console.error("Error calling AI or saving to database:", e);
		}
	}
} satisfies ExportedHandler<Env>;



