const SECRET_KEY = "your-secret-key"; // Replace with a strong secret key

import { encode } from "base64url";

// Helper function to generate a JWT
async function generateToken(payload, secret, expiresIn = 3600) {
    const header = {
        alg: "HS256",
        typ: "JWT",
    };

    const headerBase64 = encode(JSON.stringify(header));
    const payloadWithExp = {
        ...payload,
        exp: Math.floor(Date.now() / 1000) + expiresIn,
    };
    const payloadBase64 = encode(JSON.stringify(payloadWithExp));

    const data = `${headerBase64}.${payloadBase64}`;
    const key = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(secret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );

    const signature = await crypto.subtle.sign(
        "HMAC",
        key,
        new TextEncoder().encode(data)
    );

    return `${data}.${encode(new Uint8Array(signature))}`;
}

// Main function to handle login and display form or dashboard
export async function onRequest(context) {
    const { request } = context;

    if (request.method === "GET") {
        // Display the login form
        return new Response(
            `
            <html>
                <head><title>Login</title></head>
                <body>
                    <h1>Login</h1>
                    <form method="POST" action="/">
                        <label for="username">Username:</label>
                        <input type="text" id="username" name="username" required />
                        <br />
                        <label for="password">Password:</label>
                        <input type="password" id="password" name="password" required />
                        <br />
                        <button type="submit">Login</button>
                    </form>
                </body>
            </html>
            `,
            { headers: { "Content-Type": "text/html" } }
        );
    }

    if (request.method === "POST") {
        const formData = await request.formData();
        const username = formData.get("username");
        const password = formData.get("password");

        if (username === "admin" && password === "admin") {
            const token = await generateToken({ username }, SECRET_KEY);

            // Show the admin dashboard with a cookie set
            return new Response(
                `
                <html>
                    <head><title>Admin Dashboard</title></head>
                    <body>
                        <h1>Welcome to the Admin Dashboard</h1>
                        <p>You are logged in as ${username}.</p>
                    </body>
                </html>
                `,
                {
                    status: 200,
                    headers: {
                        "Content-Type": "text/html",
                        "Set-Cookie": `token=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600`,
                    },
                }
            );
        } else {
            // Show invalid credentials error and redisplay the form
            return new Response(
                `
                <html>
                    <head><title>Login</title></head>
                    <body>
                        <h1>Login</h1>
                        <p style="color: red;">Invalid credentials. Please try again.</p>
                        <form method="POST" action="/">
                            <label for="username">Username:</label>
                            <input type="text" id="username" name="username" required />
                            <br />
                            <label for="password">Password:</label>
                            <input type="password" id="password" name="password" required />
                            <br />
                            <button type="submit">Login</button>
                        </form>
                    </body>
                </html>
                `,
                { headers: { "Content-Type": "text/html" } }
            );
        }
    }

    return new Response("Method Not Allowed", { status: 405 });
}
