/**
 * Proxy: POST /api/v1/projects/list  →  backend:8000/api/v1/projects/list
 *
 * Runs server-side (Next.js Node process), so there is NO CORS.
 * The browser calls this same-origin endpoint; Next.js forwards it to FastAPI.
 */
import { NextRequest, NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

const BACKEND = process.env.BACKEND_URL ?? 'http://127.0.0.1:8000';

export async function POST(req: NextRequest) {
    try {
        const body = await req.json();
        const res = await fetch(`${BACKEND}/api/v1/projects/list`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
            signal: AbortSignal.timeout(30000), // 30s — listing projects can take time
        });
        const data = await res.json();
        return NextResponse.json(data, { status: res.status });
    } catch (err: any) {
        console.error('[proxy/v1/projects/list]', err.message);
        return NextResponse.json(
            { status: 'error', detail: err.message },
            { status: 503 }
        );
    }
}
