import { encode } from "base64url";

const SECRET_KEY = "your-secret-key"; // Replace with a strong, secure key

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

// Function to handle login and set JWT token
export async function onRequest(context) {
    const { request } = context;

    if (request.method !== "GET") {
        return new Response("Method Not Allowed", { status: 405 });
    }

    const { username, password } = await request.json();

    if (username === "admin" && password === "admin") {
        const token = await generateToken({ username }, SECRET_KEY);

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
        return new Response(
            JSON.stringify({ message: "Invalid credentials" }),
            { status: 401, headers: { "Content-Type": "application/json" } }
        );
    }
}
