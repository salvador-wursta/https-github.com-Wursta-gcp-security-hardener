/**
 * Proxy: POST /api/v1/scan/multi  →  backend:8000/api/v1/scan/multi
 *
 * Runs server-side (Next.js Node process), so there is NO CORS.
 * Uses a generous 5-minute timeout to accommodate long-running parallel scans.
 */
import { NextRequest, NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

const BACKEND = process.env.BACKEND_URL ?? 'http://127.0.0.1:8000';

export async function POST(req: NextRequest) {
    try {
        const body = await req.json();
        const res = await fetch(`${BACKEND}/api/v1/scan/multi`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
            signal: AbortSignal.timeout(300000), // 5 minutes for multi-project scans
        });
        const data = await res.json();
        return NextResponse.json(data, { status: res.status });
    } catch (err: any) {
        console.error('[proxy/v1/scan/multi]', err.message);
        return NextResponse.json(
            { status: 'error', detail: err.message },
            { status: 503 }
        );
    }
}
