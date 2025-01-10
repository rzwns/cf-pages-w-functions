import { HmacSHA256 } from 'crypto-js';

export async function onRequest(context: any) {
    const { request } = context;
    const url = new URL(request.url);
    const cookies = parseCookies(request.headers.get("Cookie"));

    // If the user is logged in (JWT present), show the admin dashboard
    if (cookies.token) {
        // Handle logout if query parameter ?t=logout is present
        if (url.searchParams.get("t") === "logout") {
            // Clear the token cookie by setting it with Max-Age=0
            return new Response(
                JSON.stringify({ message: "Logged out successfully" }),
                {
                    status: 200,
                    headers: {
                        "Set-Cookie": "token=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
                        "Content-Type": "application/json",
                    },
                }
            );
        }

        return new Response(`
            <html>
                <body>
                    <div id="app">
                        <div style="position: absolute; top: 10px; right: 10px;">
                            <button onclick="logout()">Logout</button>
                        </div>
                        <h1>Welcome to the Admin Dashboard</h1>
                        <p>You are logged in!</p>
                    </div>
                    <script>
                        function logout() {
                            fetch("?t=logout", { method: "POST" })
                                .then(response => response.json())
                                .then(data => {
                                    if (data.message === "Logged out successfully") {
                                        // On successful logout, show the login form again without reloading
                                        document.getElementById("app").innerHTML = \`
                                            <h1>Login</h1>
                                            <form id="login-form" method="POST" action="/login">
                                                <label for="username">Username:</label><br>
                                                <input type="text" id="username" name="username" required><br><br>
                                                <label for="password">Password:</label><br>
                                                <input type="password" id="password" name="password" required><br><br>
                                                <input type="submit" value="Login">
                                            </form>
                                            <p id="error-message" style="color: red; display: none;">Invalid credentials. Please try again.</p>
                                        \`;
                                        // Remove the ?t=logout parameter from the URL
                                        const url = new URL(window.location);
                                        url.searchParams.delete('t');
                                        window.history.pushState({}, '', url);
                                    }
                                });
                        }
                    </script>
                </body>
            </html>
        `, {
            status: 200,
            headers: { "Content-Type": "text/html" }
        });
    }

    // Handle the form submission (POST request)
    if (request.method === "POST" && new URL(request.url).pathname === "/login") {
        const formData = await request.formData();
        const username = formData.get("username");
        const password = formData.get("password");

        // Validate credentials
        if (username === "admin" && password === "admin") {
            // Generate the JWT token
            const secretKey = "your-very-secure-secret-key";
            const header = { alg: "HS256", typ: "JWT" };
            const payload = { sub: "1234567890", name: "Admin", iat: Math.floor(Date.now() / 1000) };
            const encodedHeader = toBase64Url(JSON.stringify(header));
            const encodedPayload = toBase64Url(JSON.stringify(payload));
            const data = `${encodedHeader}.${encodedPayload}`;

            const signature = createHmacSignature(data, secretKey);
            const jwt = `${encodedHeader}.${encodedPayload}.${signature}`;

            // Set the JWT token in a cookie
            const cookie = `token=${jwt}; HttpOnly; Secure; SameSite=Strict; Path=/`;

            return new Response(`
                <html>
                    <body>
                        <div id="app">
                            <div style="position: absolute; top: 10px; right: 10px;">
                                <button onclick="logout()">Logout</button>
                            </div>
                            <h1>Welcome to the Admin Dashboard</h1>
                            <p>You are logged in!</p>
                        </div>
                        <script>
                            function logout() {
                                fetch("?t=logout", { method: "POST" })
                                    .then(response => response.json())
                                    .then(data => {
                                        if (data.message === "Logged out successfully") {
                                            // On successful logout, show the login form again without reloading
                                            document.getElementById("app").innerHTML = \`
                                                <h1>Login</h1>
                                                <form id="login-form" method="POST" action="/login">
                                                    <label for="username">Username:</label><br>
                                                    <input type="text" id="username" name="username" required><br><br>
                                                    <label for="password">Password:</label><br>
                                                    <input type="password" id="password" name="password" required><br><br>
                                                    <input type="submit" value="Login">
                                                </form>
                                                <p id="error-message" style="color: red; display: none;">Invalid credentials. Please try again.</p>
                                            \`;
                                            // Remove the ?t=logout parameter from the URL
                                            const url = new URL(window.location);
                                            url.searchParams.delete('t');
                                            window.history.pushState({}, '', url);
                                        }
                                    });
                            }
                        </script>
                    </body>
                </html>
            `, {
                status: 200,
                headers: { "Set-Cookie": cookie, "Content-Type": "text/html" }
            });
        } else {
            // Invalid credentials error
            return new Response(`
                <html>
                    <body>
                        <div id="app">
                            <h1>Login</h1>
                            <form id="login-form" method="POST" action="/login">
                                <label for="username">Username:</label><br>
                                <input type="text" id="username" name="username" required><br><br>
                                <label for="password">Password:</label><br>
                                <input type="password" id="password" name="password" required><br><br>
                                <input type="submit" value="Login">
                            </form>
                            <p id="error-message" style="color: red; display: none;">Invalid credentials. Please try again.</p>
                        </div>
                        <script>
                            document.getElementById("login-form").addEventListener("submit", async function(event) {
                                event.preventDefault();
                                
                                const formData = new FormData(this);
                                const response = await fetch("/login", {
                                    method: "POST",
                                    body: formData
                                });
                                
                                const text = await response.text();
                                if (response.status === 200) {
                                    document.getElementById("app").innerHTML = text;
                                } else {
                                    document.getElementById("error-message").style.display = "block";
                                }
                            });
                        </script>
                    </body>
                </html>
            `, {
                status: 401,
                headers: { "Content-Type": "text/html" }
            });
        }
    }

    // Default login form if not logged in
    return new Response(`
        <html>
            <body>
                <div id="app">
                    <h1>Login</h1>
                    <form id="login-form" method="POST" action="/login">
                        <label for="username">Username:</label><br>
                        <input type="text" id="username" name="username" required><br><br>
                        <label for="password">Password:</label><br>
                        <input type="password" id="password" name="password" required><br><br>
                        <input type="submit" value="Login">
                    </form>
                    <p id="error-message" style="color: red; display: none;">Invalid credentials. Please try again.</p>
                </div>
                <script>
                    document.getElementById("login-form").addEventListener("submit", async function(event) {
                        event.preventDefault();
                        
                        const formData = new FormData(this);
                        const response = await fetch("/login", {
                            method: "POST",
                            body: formData
                        });
                        
                        const text = await response.text();
                        if (response.status === 200) {
                            document.getElementById("app").innerHTML = text;
                        } else {
                            document.getElementById("error-message").style.display = "block";
                        }
                    });
                </script>
            </body>
        </html>
    `, {
        headers: { "Content-Type": "text/html" }
    });
}

// Helper function to Base64Url encode a string
function toBase64Url(str: string): string {
    return btoa(str)
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
}

// Helper function to create an HMAC-SHA256 signature
function createHmacSignature(data: string, key: string): string {
    return HmacSHA256(data, key).toString();
}

// Helper function to parse cookies
function parseCookies(cookieHeader: string | null): { [key: string]: string } {
    const cookies: { [key: string]: string } = {};
    if (!cookieHeader) return cookies;
    cookieHeader.split(";").forEach(cookie => {
        const [key, value] = cookie.trim().split("=");
        cookies[key] = value;
    });
    return cookies;
}