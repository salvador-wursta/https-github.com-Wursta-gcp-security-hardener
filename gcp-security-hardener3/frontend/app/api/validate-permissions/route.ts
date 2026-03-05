/**
 * Proxy: GET /api/validate-permissions  →  backend:8000/api/validate-permissions
 * Runs server-side (Next.js Node process), so there is NO CORS.
 */
import { NextRequest, NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

const BACKEND = process.env.BACKEND_URL ?? 'http://127.0.0.1:8000';

export async function GET(req: NextRequest) {
    try {
        const { searchParams } = new URL(req.url);
        const sa_email = searchParams.get('sa_email');
        const target_id = searchParams.get('target_id');
        const scope = searchParams.get('scope') || 'project';

        if (!sa_email || !target_id) {
            return NextResponse.json(
                { status: 'error', detail: 'Missing sa_email or target_id' },
                { status: 400 }
            );
        }

        const backendUrl = new URL(`${BACKEND}/api/validate-permissions`);
        backendUrl.searchParams.set('sa_email', sa_email);
        backendUrl.searchParams.set('target_id', target_id);
        backendUrl.searchParams.set('scope', scope);

        const res = await fetch(backendUrl.toString(), {
            method: 'GET',
            headers: { 'Content-Type': 'application/json' },
            signal: AbortSignal.timeout(15000),
        });

        const data = await res.json();
        return NextResponse.json(data, { status: res.status });
    } catch (err: any) {
        console.error('[proxy/validate-permissions]', err.message);
        return NextResponse.json(
            { status: 'error', detail: err.message },
            { status: 503 }
        );
    }
}
