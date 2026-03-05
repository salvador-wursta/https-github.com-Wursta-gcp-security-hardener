/**
 * Proxy: GET /api/verify-access/[resourceId]  →  backend:8000/api/verify-access/[resourceId]
 */
import { NextRequest, NextResponse } from 'next/server';

const BACKEND = process.env.BACKEND_URL ?? 'http://127.0.0.1:8000';

export async function GET(
    req: NextRequest,
    { params }: { params: { resourceId: string } }
) {
    const { resourceId } = params;
    const scope = req.nextUrl.searchParams.get('scope') ?? 'project';
    try {
        const res = await fetch(
            `${BACKEND}/api/verify-access/${encodeURIComponent(resourceId)}?scope=${scope}`,
            { signal: AbortSignal.timeout(10000) }
        );
        const data = await res.json();
        return NextResponse.json(data, { status: res.status });
    } catch (err: any) {
        console.error('[proxy/verify-access]', err.message);
        return NextResponse.json({ status: 'error', detail: err.message }, { status: 503 });
    }
}
