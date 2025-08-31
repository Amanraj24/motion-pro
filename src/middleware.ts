// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import jwt from 'jsonwebtoken';
export const runtime = "nodejs";


interface DecodedToken {
  id: number;
  email: string;
  name: string;
  iat: number;
  exp: number;
}

export function middleware(request: NextRequest): NextResponse {
  const { pathname } = request.nextUrl;

  // Define protected routes
  const protectedRoutes: string[] = ['/dashboard', '/profile', '/settings'];
  const authRoutes: string[] = ['/login', '/signup', '/verify-email', '/forgot-password', '/reset-password'];

  // Check if the current path is protected
  const isProtectedRoute = protectedRoutes.some((route: string) => 
    pathname.startsWith(route)
  );

  // Check if the current path is an auth route
  const isAuthRoute = authRoutes.some((route: string) => 
    pathname.startsWith(route)
  );

  // Get the token from cookies
  const token = request.cookies.get('auth-token')?.value;
  // const token="Aman1234";

  // If it's a protected route and no token, redirect to login
  if (isProtectedRoute && !token) {
    return NextResponse.redirect(new URL('/login', request.url));
  }

  // If token exists, verify it
  if (token) {
    try {
      const decoded = jwt.verify(token,"Aman1234") as DecodedToken;
      
      // If user is authenticated and trying to access auth routes, redirect to dashboard
      if (isAuthRoute) {
        return NextResponse.redirect(new URL('/dashboard', request.url));
      }

      // Add user info to request headers for API routes
      const requestHeaders = new Headers(request.headers);
      requestHeaders.set('user-id', decoded.id.toString());
      requestHeaders.set('user-email', decoded.email);

      return NextResponse.next({
        request: {
          headers: requestHeaders,
        },
      });

    } catch (error) {
      // Invalid token, clear it and redirect to login if accessing protected route
      const response = isProtectedRoute 
        ? NextResponse.redirect(new URL('/login', request.url))
        : NextResponse.next();

      response.cookies.set('auth-token', '', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 0,
        path: '/'
      });

      return response;
    }
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api (API routes)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    '/((?!api|_next/static|_next/image|favicon.ico).*)',
  ],
};