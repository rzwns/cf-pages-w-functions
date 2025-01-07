import { SignJWT, jwtVerify } from 'jose';

const SECRET_KEY = new TextEncoder().encode('your-secret-key'); // Use Uint8Array for keys
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

// Main function handling requests
export async function onRequest(context) {
    const { request } = context;
    const url = new URL(request.url);

    if (url.pathname === '/login' && request.method === 'POST') {
        const { username, password } = await request.json();
        if (username === USERNAME && password === PASSWORD) {
            const token = await new SignJWT({ username })
                .setProtectedHeader({ alg: 'HS256' })
                .setExpirationTime('1h')
                .sign(SECRET_KEY);

            return new Response(JSON.stringify({ message: 'Login successful' }), {
                status: 200,
                headers: {
                    'Content-Type': 'application/json',
                    'Set-Cookie': setCookie(token),
                },
            });
        } else {
            return new Response(JSON.stringify({ message: 'Invalid credentials' }), {
                status: 401,
                headers: { 'Content-Type': 'application/json' },
            });
        }
    }

    if (url.pathname === '/logout') {
        return new Response(JSON.stringify({ message: 'Logged out successfully' }), {
            status: 200,
            headers: {
                'Set-Cookie': 'token=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0',
                'Content-Type': 'application/json',
            },
        });
    }

    const cookies = request.headers.get('Cookie');
    const token = getCookie(cookies, 'token');

    if (url.pathname === '/admin') {
        if (!token) {
            return Response.redirect('/login');
        }

        try {
            const { payload } = await jwtVerify(token, SECRET_KEY);
            return new Response(`
                <html>
                    <body>
                        <h1>Admin Dashboard</h1>
                        <p>Welcome, ${payload.username}!</p>
                        <a href="/logout">Logout</a>
                    </body>
                </html>
            `, {
                status: 200,
                headers: { 'Content-Type': 'text/html' },
            });
        } catch (err) {
            return Response.redirect('/login');
        }
    }

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
                                headers: { 'Content-Type': 'application/json' },
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
        `, {
            status: 200,
            headers: { 'Content-Type': 'text/html' },
        });
    }

    return new Response('Not Found', { status: 404 });
}
