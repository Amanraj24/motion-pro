import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { jwtVerify } from 'jose';
const secret = new TextEncoder().encode(process.env.JWT_SECRET as string);

export async function middleware(request: NextRequest) {
  try {
    const { pathname } = request.nextUrl;

    // Define which routes require auth and which are only for guests
    const protectedRoutes = ['/dashboard', '/profile', '/settings'];
    const authRoutes = ['/login', '/signup', '/verify-email', '/forgot-password', '/reset-password'];

    const isProtectedRoute = protectedRoutes.some((route) => pathname.startsWith(route));
    const isAuthRoute = authRoutes.some((route) => pathname.startsWith(route));

    const token = request.cookies.get('auth-token')?.value;

    // If no token and trying to access protected page → kick to login
    if (isProtectedRoute && !token) {
      return NextResponse.redirect(new URL('/login', request.url));
    }

    if (token) {
      try {
        const { payload } = await jwtVerify(token, secret);

        // Block access to auth pages if already logged in
        if (isAuthRoute) {
          return NextResponse.redirect(new URL('/dashboard', request.url));
        }

        // ✅ Inject user data into request headers (Edge-compatible)
        const requestHeaders = new Headers(request.headers);
        if (payload?.id) requestHeaders.set('x-user-id', String(payload.id));
        if (payload?.email) requestHeaders.set('x-user-email', String(payload.email));

        return NextResponse.next({
          request: { headers: requestHeaders },
        });

      } catch (err) {
        console.error("JWT verification failed:", err);

        // Invalid/expired token → clear cookie + redirect if needed
        const response = isProtectedRoute
          ? NextResponse.redirect(new URL('/login', request.url))
          : NextResponse.next();

        response.cookies.set('auth-token', '', {
          httpOnly: true,
          secure: true,
          sameSite: 'strict',
          maxAge: 0,
          path: '/',
        });

        return response;
      }
    }

    // Default: let request through
    return NextResponse.next();
  } catch (err) {
    console.error("Middleware error:", err);
    return NextResponse.redirect(new URL('/login', request.url));
  }
}

// ✅ Exclude next internals & API routes
export const config = {
  matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'],
};