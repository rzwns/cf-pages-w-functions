export async function onRequest(context) {
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
