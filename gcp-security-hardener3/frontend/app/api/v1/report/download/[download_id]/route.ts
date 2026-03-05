/**
 * Proxy: GET /api/v1/report/download/[download_id]  →  backend:8000/api/v1/report/download/<id>
 *
 * CRITICAL: This must be a same-origin GET proxy so that the frontend can use
 * <a href="/api/v1/report/download/..." download="filename.pdf"> to trigger a native
 * browser file download. Cross-origin anchor downloads are ignored by Chrome — the
 * download attribute only works for same-origin URLs.
 *
 * Also: window.open() after async/await is killed by Chrome popup blocker silently.
 * Anchor click is the only reliable cross-browser download trigger.
 */
import { NextRequest, NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

const BACKEND = process.env.BACKEND_URL ?? 'http://localhost:8000';

export async function GET(
    req: NextRequest,
    context: { params: Promise<{ download_id: string }> }
) {
    const params = await context.params;
    const { download_id } = params;

    if (!download_id) {
        return NextResponse.json({ error: 'Missing download_id' }, { status: 400 });
    }

    try {
        const backendUrl = `${BACKEND}/api/v1/report/download/${download_id}`;
        const res = await fetch(backendUrl, { method: 'GET' });

        if (!res.ok) {
            const text = await res.text();
            return NextResponse.json(
                { error: 'Download failed', detail: text },
                { status: res.status }
            );
        }

        const contentDisposition = res.headers.get('Content-Disposition') ??
            `attachment; filename="gcp_security_report.pdf"`;

        const proxyHeaders = new Headers();
        proxyHeaders.set('Content-Type', 'application/pdf');
        proxyHeaders.set('Content-Disposition', contentDisposition);

        const contentLength = res.headers.get('Content-Length');
        if (contentLength) {
            proxyHeaders.set('Content-Length', contentLength);
        }

        // Pass the readable stream directly to avoid binary data corruption in node Buffer conversions
        return new NextResponse(res.body, {
            status: 200,
            headers: proxyHeaders,
        });
    } catch (err: any) {
        console.error('[proxy/report/download]', err.message);
        return NextResponse.json({ error: 'Proxy error', detail: err.message }, { status: 503 });
    }
}
