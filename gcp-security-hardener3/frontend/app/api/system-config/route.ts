/**
 * Proxy: GET /api/system-config  →  backend:8000/api/system-config
 *
 * Runs server-side (Next.js Node process), so there is NO CORS.
 * The browser calls this same-origin endpoint; Next.js forwards it to FastAPI.
 */
import { NextRequest, NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

const BACKEND = process.env.BACKEND_URL ?? 'http://127.0.0.1:8000';

export async function GET(req: NextRequest) {
    try {
        const res = await fetch(`${BACKEND}/api/system-config`, {
            cache: 'no-store',
            signal: AbortSignal.timeout(8000),
        });
        const data = await res.json();
        return NextResponse.json(data, { status: res.status });
    } catch (err: any) {
        console.error('[proxy/system-config]', err.message);
        return NextResponse.json(
            { service_account_email: 'Backend Offline', source: 'proxy-error', detail: err.message },
            { status: 503 }
        );
    }
}
