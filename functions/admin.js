// admin.js

const SECRET_KEY = 'your-secret-key'; // Secret key for JWT signing, keep this safe
const USERNAME = 'admin';
const PASSWORD = 'admin';

// Helper function to set a cookie
function setCookie(token) {
    return `token=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600`;
}

// Helper function to get a cookie value by name
function getCookie(cookies, name) {
    const match = cookies && cookies.split(';').find(cookie => cookie.trim().startsWith(name + '='));
    return match ? match.split('=')[1] : null;
}

// Base64 URL decode function
function base64UrlDecode(str) {
    return JSON.parse(decodeURIComponent(atob(str.replace(/-/g, '+').replace(/_/g, '/'))));
}

// Function to create HMAC SHA256 signature
function createHmacSignature(data, secret) {
    const crypto = require('crypto');
    return crypto.createHmac('sha256', secret).update(data).digest('base64url');
}

// Function to verify JWT
function verifyJwt(token) {
    const [header, payload, signature] = token.split('.');
    
    // Decode the header and payload
    const decodedHeader = base64UrlDecode(header);
    const decodedPayload = base64UrlDecode(payload);

    // Check if the token is expired
    if (decodedPayload.exp && Date.now() >= decodedPayload.exp * 1000) {
        throw new Error('Token expired');
    }

    // Recreate the signature
    const data = `${header}.${payload}`;
    const expectedSignature = createHmacSignature(data, SECRET_KEY);

    // Compare the recreated signature with the token's signature
    if (expectedSignature !== signature) {
        throw new Error('Invalid token');
    }

    return decodedPayload; // Return the decoded payload if verification is successful
}

// Main function handling requests
export async function onRequest(context) {
    const { request } = context;
    const url = new URL(request.url);

    // Handle Login Form Submission (POST)
    if (url.pathname === '/login' && request.method === 'POST') {
        const { username, password } = await request.json();

        // Check if credentials match
        if (username === USERNAME && password === PASSWORD) {
            const exp = Math.floor(Date.now() / 1000) + (60 * 60); // 1 hour expiration
            const payload = { username, exp };
            const header = { alg: 'HS256', typ: 'JWT' };

            // Create the token
            const token = `${btoa(JSON.stringify(header))}.${btoa(JSON.stringify(payload))}.${createHmacSignature(`${btoa(JSON.stringify(header))}.${btoa(JSON.stringify(payload))}`, SECRET_KEY)}`;

            return new Response(JSON.stringify({ message: 'Login successful' }), {
                status: 200,
                headers: {
                    'Content-Type': 'application/json',
                    'Set-Cookie': setCookie(token), // Set JWT token in HttpOnly cookie
                },
            });
        } else {
            return new Response(JSON.stringify({ message: 'Invalid credentials' }), {
                status: 401,
                headers: { 'Content-Type': 'application/json' },
            });
        }
    }

    // Handle Logout (GET) - Clear the JWT cookie
    if (url.pathname === '/logout') {
        return new Response(JSON.stringify({ message: 'Logged out successfully' }), {
            status: 200,
            headers: {
                'Set-Cookie': 'token=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0', // Clear token
                'Content-Type': 'application/json',
            },
        });
    }

    // Check if the user is authenticated (has a valid JWT token)
    const cookies = request.headers.get('Cookie');
    const token = getCookie(cookies, 'token');

    // Admin Dashboard (GET)
    if (url.pathname === '/admin') {
        if (!token) {
            // If no token, redirect to login page
            return Response.redirect('/login');
        }

        try {
            // Verify the token
            const decoded = verifyJwt(token);

            // If token is valid, show the admin dashboard
            return new Response(`
                <html>
                    <body>
                        <h1>Admin Dashboard</h1>
                        <p>Welcome, ${decoded.username}!</p>
                        <a href="/logout">Logout</a>
                    </body>
                </html>
            `, {
                status: 200,
                headers: { 'Content-Type': 'text/html' },
            });
        } catch (err) {
            // Invalid or expired token, redirect to login page
            return Response.redirect('/login');
        }
    }

    // If no valid path is found, return the login page (GET)
    if (url.pathname === '/login') {
        return new Response(`
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
                                headers: {
                                    'Content-Type': 'application/json',
                                }
                            });

                            const data = await response.json();

                            if (response.ok) {
                                window.location.href = '/admin';  // Redirect to admin page after successful login
                            } else {
                                alert(data.message);  // Show error message
                            }
                        });
                    </script>
                </body>
            </html>
        `, {
            status: 200,
            headers: { 'Content-Type': 'text/html' },
        });
    }

    // If route doesn't match, return 404
    return new Response('Not Found', { status: 404 });
}
