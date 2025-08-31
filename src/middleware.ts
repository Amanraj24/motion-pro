// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { jwtVerify } from 'jose';

interface DecodedToken {
  id: number;
  email: string;
  name: string;
  iat: number;
  exp: number;
}

const secret = new TextEncoder().encode("Aman1234");

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Define protected and auth routes
  const protectedRoutes: string[] = ['/dashboard', '/profile', '/settings'];
  const authRoutes: string[] = ['/login', '/signup', '/verify-email', '/forgot-password', '/reset-password'];

  const isProtectedRoute = protectedRoutes.some((route) => pathname.startsWith(route));
  const isAuthRoute = authRoutes.some((route) => pathname.startsWith(route));

  const token = request.cookies.get('auth-token')?.value;

  // If it's a protected route and no token → redirect to login
  if (isProtectedRoute && !token) {
    return NextResponse.redirect(new URL('/login', request.url));
  }

  if (token) {
    try {
      const { payload } = await jwtVerify(token, secret);
      const decoded = payload as unknown as DecodedToken;

      // If authenticated user tries to access auth routes → redirect to dashboard
      if (isAuthRoute) {
        return NextResponse.redirect(new URL('/dashboard', request.url));
      }

      // Add user info to request headers
      const requestHeaders = new Headers(request.headers);
      requestHeaders.set('user-id', decoded.id.toString());
      requestHeaders.set('user-email', decoded.email);

      return NextResponse.next({
        request: {
          headers: requestHeaders,
        },
      });

    } catch (error) {
      // Invalid token → clear and redirect if protected route
      const response = isProtectedRoute
        ? NextResponse.redirect(new URL('/login', request.url))
        : NextResponse.next();

      response.cookies.set('auth-token', '', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 0,
        path: '/',
      });

      return response;
    }
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    '/((?!api|_next/static|_next/image|favicon.ico).*)',
  ],
};
