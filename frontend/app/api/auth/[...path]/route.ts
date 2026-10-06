import { NextRequest, NextResponse } from 'next/server';

const allowed: Record<string, string[]> = {
  signup: ['POST'], login: ['POST'], enroll: ['GET'],
  'enroll/confirm': ['POST'], verify: ['POST'], me: ['GET'], logout: ['POST'],
  messages: ['GET', 'POST'],
  users: ['GET'],
};
const cookie = 'keyclock_session';

async function handler(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  const path = (await context.params).path.join('/');
  if (!allowed[path]?.includes(request.method)) {
    return NextResponse.json({ detail: 'Not found' }, { status: 404 });
  }
  const origin = process.env.APP_ORIGIN;
  const backend = process.env.BACKEND_URL;
  const key = process.env.INTERNAL_API_KEY;
  if (!origin || !backend || !key) {
    return NextResponse.json({ detail: 'Server configuration is incomplete.' }, { status: 503 });
  }
  if (request.method === 'POST' && request.headers.get('origin') !== origin) {
    return NextResponse.json({ detail: 'Invalid request origin.' }, { status: 403 });
  }
  let body: string | undefined;
  if (request.method === 'POST') {
    if (!request.headers.get('content-type')?.startsWith('application/json')) {
      return NextResponse.json({ detail: 'JSON required.' }, { status: 415 });
    }
    body = await request.text();
    if (body.length > (path === 'messages' ? 16384 : 4096)) return NextResponse.json({ detail: 'Request too large.' }, { status: 413 });
  }
  try {
    const query = new URLSearchParams();
    if (path === 'users' && request.nextUrl.searchParams.has('after')) query.set('after', request.nextUrl.searchParams.get('after')!);
    const upstream = await fetch(`${backend.replace(/\/$/, '')}/auth/${path}${query.size ? `?${query}` : ''}`, {
      method: request.method,
      headers: {
        'Content-Type': 'application/json', 'X-Internal-Key': key,
        Authorization: `Bearer ${request.cookies.get(cookie)?.value ?? ''}`,
      },
      body, cache: 'no-store', signal: AbortSignal.timeout(20000), redirect: 'error',
    });
    const data = await upstream.json();
    const token = data.token;
    delete data.token;
    // Keep validation details readable without reflecting submitted credentials.
    if (Array.isArray(data.detail)) {
      const invalidName = data.detail.some((issue: { loc?: unknown[] }) => issue.loc?.includes('name'));
      data.detail = path === 'messages' ? 'Enter a valid recipient email and a message of 1–2,000 characters.' : invalidName ? 'Enter a name between 1 and 100 characters.' : 'Check your email and use a password of 12–128 characters.';
    }
    const response = NextResponse.json(data, { status: upstream.status, headers: { 'Cache-Control': 'no-store' } });
    if (upstream.headers.has('retry-after')) response.headers.set('Retry-After', upstream.headers.get('retry-after')!);
    if (upstream.ok && token) {
      response.cookies.set(cookie, token, {
        httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', path: '/',
        maxAge: data.step === 'session' ? 3600 : data.step === 'enroll' ? 600 : 300,
      });
    }
    if ((path === 'logout' && upstream.ok) || (path === 'me' && upstream.status === 401)) response.cookies.delete(cookie);
    return response;
  } catch {
    return NextResponse.json({ detail: 'The authentication server is unavailable. Please try again.' }, { status: 502 });
  }
}

export { handler as GET, handler as POST };
