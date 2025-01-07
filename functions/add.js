export function onRequest(context) {
    // Define your secret key
    const secretKey = "your-very-secure-secret-key";
  
    // Create the JWT header
    const header = {
      alg: "HS256",
      typ: "JWT",
    };
  
    // Create the JWT payload
    const payload = {
      sub: "1234567890",
      name: "John Doe",
      iat: Math.floor(Date.now() / 1000),
    };
  
    // Encode the header and payload as Base64Url
    const encodedHeader = toBase64Url(JSON.stringify(header));
    const encodedPayload = toBase64Url(JSON.stringify(payload));
  
    // Create the signature
    const data = `${encodedHeader}.${encodedPayload}`;
    return createHmacSignature(data, secretKey).then((signature) => {
      // Combine header, payload, and signature to form the JWT
      const jwt = `${encodedHeader}.${encodedPayload}.${signature}`;
  
      // Set the JWT token as a cookie with the SameSite attribute
      const cookie = `token=${jwt}; HttpOnly; Secure; SameSite=Strict; Path=/`;
  
      // Return a response with the cookie
      return new Response("Token set in cookies.", {
        headers: {
          "Content-Type": "text/plain",
          "Set-Cookie": cookie,
        },
      });
    });
  }
  
  // Helper function to Base64Url encode a string
  function toBase64Url(str) {
    return btoa(str)
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");
  }
  
  // Helper function to create an HMAC-SHA256 signature
  async function createHmacSignature(data, key) {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(key);
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      keyData,
      { name: "HMAC", hash: { name: "SHA-256" } },
      false,
      ["sign"]
    );
    const signatureBuffer = await crypto.subtle.sign(
      "HMAC",
      cryptoKey,
      encoder.encode(data)
    );
    return toBase64Url(String.fromCharCode(...new Uint8Array(signatureBuffer)));
  }
  