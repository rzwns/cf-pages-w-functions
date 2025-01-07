import { decode } from "base64url";

const SECRET_KEY = "your-secret-key";

// Helper function to verify JWT
async function verifyToken(token, secret) {
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

// Function to verify if the user is logged in
export async function onRequest(context) {
    const { request } = context;

    const cookies = request.headers.get("Cookie");
    const token = cookies
        ?.split(";")
        .find((cookie) => cookie.trim().startsWith("token="))
        ?.split("=")[1];

    if (!token) {
        return new Response("Unauthorized", { status: 401 });
    }

    try {
        const payload = await verifyToken(token, SECRET_KEY);
        return new Response(JSON.stringify(payload), {
            status: 200,
            headers: { "Content-Type": "application/json" },
        });
    } catch (err) {
        return new Response("Unauthorized", { status: 401 });
    }
}
