import { encode, decode } from "base64url";

const SECRET_KEY = "your-secret-key"; // Replace with a strong, secure key
const USERNAME = "admin";
const PASSWORD = "admin";

// Helper function to sign a JWT
async function signJWT(payload, secret, expiresIn = 3600) {
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

// Helper function to verify a JWT
async function verifyJWT(token, secret) {
    const [headerBase64, payloadBase64, signatureBase64] = token.split(".");
    if (!headerBase64 || !payloadBase64 || !signatureBase64) {
        throw new Error("Invalid token");
    }

    const data = `${headerBase64}.${payloadBase64}`;
    const key = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(secret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["verify"]
    );

    const valid = await crypto.subtle.verify(
        "HMAC",
        key,
        decode(signatureBase64),
        new TextEncoder().encode(data)
    );

    if (!valid) {
        throw new Error("Invalid signature");
    }

    const payload = JSON.parse(decode(payloadBase64));
    if (payload.exp < Math.floor(Date.now() / 1000)) {
        throw new Error("Token expired");
    }

    return payload;
}

// Main function handling requests
export async function onRequest(context) {
    const { request } = context;
    const url = new URL(request.url);

    if (url.pathname === "/login" && request.method === "POST") {
        const { username, password } = await request.json();

        if (username === USERNAME && password === PASSWORD) {
            const token = await signJWT({ username }, SECRET_KEY);
            return new Response(
                JSON.stringify({ message: "Login successful" }),
                {
                    status: 200,
                    headers: {
                        "Content-Type": "application/json",
                        "Set-Cookie": `token=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600`,
                    },
                }
            );
        } else {
            return new Response(JSON.stringify({ message: "Invalid credentials" }), {
                status: 401,
                headers: { "Content-Type": "application/json" },
            });
        }
    }

    if (url.pathname === "/logout") {
        return new Response(JSON.stringify({ message: "Logged out successfully" }), {
            status: 200,
            headers: {
                "Set-Cookie": "token=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
                "Content-Type": "application/json",
            },
        });
    }

    if (url.pathname === "/admin") {
        const cookies = request.headers.get("Cookie");
        const token = cookies
            ?.split(";")
            .find((cookie) => cookie.trim().startsWith("token="))
            ?.split("=")[1];

        if (!token) {
            return Response.redirect("/login");
        }

        try {
            const decoded = await verifyJWT(token, SECRET_KEY);
            return new Response(
                `
                <html>
                    <body>
                        <h1>Admin Dashboard</h1>
                        <p>Welcome, ${decoded.username}!</p>
                        <a href="/logout">Logout</a>
                    </body>
                </html>
                `,
                { status: 200, headers: { "Content-Type": "text/html" } }
            );
        } catch (err) {
            return Response.redirect("/login");
        }
    }

    if (url.pathname === "/login") {
        return new Response(
            `
            <html>
                <body>
                    <h1>Login</h1>
                    <form id="login-form">
                        <label for="username">Username: </label>
                        <input type="text" id="username" name="username" required><br><br>
                        
                        <label for="password">Password: </label>
                        <input type="password" id="password" name="password" required><br><br>
                        
                        <button type="submit">Login</button>
                    </form>
                    <script>
                        document.getElementById('login-form').addEventListener('submit', async function(event) {
                            event.preventDefault();
                            const username = document.getElementById('username').value;
                            const password = document.getElementById('password').value;

                            const response = await fetch('/login', {
                                method: 'POST',
                                body: JSON.stringify({ username, password }),
                                headers: { 'Content-Type': 'application/json' }
                            });

                            const data = await response.json();
                            if (response.ok) {
                                window.location.href = '/admin';
                            } else {
                                alert(data.message);
                            }
                        });
                    </script>
                </body>
            </html>
            `,
            { status: 200, headers: { "Content-Type": "text/html" } }
        );
    }

    return new Response("Not Found", { status: 404 });
}
