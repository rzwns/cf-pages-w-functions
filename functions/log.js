export async function onRequest(context) {
    const { request } = context;
    const url = new URL(request.url);
    const cookies = parseCookies(request.headers.get("Cookie"));
    
    // Check if user is already logged in by looking for JWT cookie
    if (cookies.token) {
      // Redirect to the admin dashboard if logged in
      return new Response(`
        <html>
          <body>
            <h1>Welcome to the Admin Dashboard</h1>
            <p>You are logged in!</p>
          </body>
        </html>
      `, {
        headers: { "Content-Type": "text/html" }
      });
    }
  
    // Check if the form is submitted (POST request)
    if (request.method === "POST") {
      const formData = await request.formData();
      const username = formData.get("username");
      const password = formData.get("password");
  
      // Validate the credentials
      if (username === "admin" && password === "admin") {
        // Create the JWT token
        const secretKey = "your-very-secure-secret-key";
        const header = {
          alg: "HS256",
          typ: "JWT",
        };
        const payload = {
          sub: "1234567890",
          name: "Admin",
          iat: Math.floor(Date.now() / 1000),
        };
        const encodedHeader = toBase64Url(JSON.stringify(header));
        const encodedPayload = toBase64Url(JSON.stringify(payload));
        const data = `${encodedHeader}.${encodedPayload}`;
        
        const signature = await createHmacSignature(data, secretKey);
        const jwt = `${encodedHeader}.${encodedPayload}.${signature}`;
  
        // Set the JWT token in a cookie
        const cookie = `token=${jwt}; HttpOnly; Secure; SameSite=Strict; Path=/`;
  
        return new Response(`
          <html>
            <body>
              <h1>Login Successful</h1>
              <p>Redirecting to the admin dashboard...</p>
              <script>setTimeout(() => { window.location.href = "/"; }, 2000);</script>
            </body>
          </html>
        `, {
          status: 200,
          headers: {
            "Set-Cookie": cookie,
            "Content-Type": "text/html"
          }
        });
      } else {
        // Invalid credentials, show error
        return new Response(`
          <html>
            <body>
              <h1>Invalid Credentials</h1>
              <p>The username or password you entered is incorrect.</p>
              <a href="/">Back to Login</a>
            </body>
          </html>
        `, {
          status: 401,
          headers: { "Content-Type": "text/html" }
        });
      }
    }
  
    // Show the login form if no JWT is found or on GET request
    return new Response(`
      <html>
        <body>
          <h1>Login</h1>
          <form method="POST">
            <label for="username">Username:</label><br>
            <input type="text" id="username" name="username" required><br><br>
            <label for="password">Password:</label><br>
            <input type="password" id="password" name="password" required><br><br>
            <input type="submit" value="Login">
          </form>
        </body>
      </html>
    `, {
      headers: { "Content-Type": "text/html" }
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
  
  // Helper function to parse cookies
  function parseCookies(cookieHeader) {
    const cookies = {};
    if (!cookieHeader) return cookies;
    cookieHeader.split(";").forEach(cookie => {
      const [key, value] = cookie.trim().split("=");
      cookies[key] = value;
    });
    return cookies;
  }
  