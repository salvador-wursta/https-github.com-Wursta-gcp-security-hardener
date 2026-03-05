/**
 * Proxy: GET /api/session/identity  →  backend:8000/api/session/identity
 * Returns the currently active scanner SA email stored in backend memory.
 */
import { NextRequest, NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

const BACKEND = process.env.BACKEND_URL ?? 'http://127.0.0.1:8000';

export async function GET(req: NextRequest) {
    try {
        const res = await fetch(`${BACKEND}/api/session/identity`, {
            method: 'GET',
            signal: AbortSignal.timeout(5000),
        });
        const data = await res.json();
        return NextResponse.json(data, { status: res.status });
    } catch (err: any) {
        console.error('[proxy/session/identity]', err.message);
        return NextResponse.json({ active: false, sa_email: null }, { status: 200 });
    }
}
