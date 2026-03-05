/**
 * Proxy: POST /api/session/activate  →  backend:8000/api/session/activate
 * Runs server-side (Next.js Node process), so there is NO CORS.
 */
import { NextRequest, NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

const BACKEND = process.env.BACKEND_URL ?? 'http://127.0.0.1:8000';

export async function POST(req: NextRequest) {
    try {
        const body = await req.json();
        const res = await fetch(`${BACKEND}/api/session/activate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
            signal: AbortSignal.timeout(10000),
        });
        const data = await res.json();
        return NextResponse.json(data, { status: res.status });
    } catch (err: any) {
        console.error('[proxy/session/activate]', err.message);
        return NextResponse.json(
            { status: 'error', detail: err.message },
            { status: 503 }
        );
    }
}
