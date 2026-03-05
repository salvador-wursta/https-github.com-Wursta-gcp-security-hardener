/**
 * Proxy: POST /api/v1/report/generate-pdf  →  backend:8000/api/v1/report/generate-pdf
 *
 * Runs server-side (Next.js Node process), so there is NO CORS.
 * Streams the PDF bytes directly through to the browser.
 * Supports arbitrarily large PDFs (2-5000+ pages) without timeouts.
 */
import { NextRequest, NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

// Large reports can take a while — 5 min timeout
export const maxDuration = 300;

const BACKEND = process.env.BACKEND_URL ?? 'http://127.0.0.1:8000';

export async function POST(req: NextRequest) {
    try {
        const body = await req.json();
        const jitToken = req.headers.get('X-JIT-Token') ?? '';
        const { searchParams } = new URL(req.url);
        const orgName = searchParams.get('org_name') ?? '';
        const analystName = searchParams.get('analyst_name') ?? '';

        const backendUrl = new URL(`${BACKEND}/api/v1/report/generate-pdf`);
        if (orgName) backendUrl.searchParams.set('org_name', orgName);
        if (analystName) backendUrl.searchParams.set('analyst_name', analystName);

        const res = await fetch(backendUrl.toString(), {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-JIT-Token': jitToken,
            },
            body: JSON.stringify(body),
            // No signal timeout — let the backend take as long as needed
        });

        if (!res.ok) {
            const text = await res.text();
            return NextResponse.json(
                { error: 'PDF generation failed', detail: text },
                { status: res.status }
            );
        }

        // Stream the PDF bytes + filename from backend's Content-Disposition
        const pdfBytes = await res.arrayBuffer();
        const contentDisposition = res.headers.get('Content-Disposition') ??
            `attachment; filename="security_report.pdf"`;

        // Extract clean filename for the X-Filename header
        const fnMatch = contentDisposition.match(/filename[^;=\n]*=(['"]?)([^'"\n;]+)\1/);
        const cleanFilename = fnMatch ? fnMatch[2].trim() : `gcp_security_report_${new Date().toISOString().split('T')[0]}.pdf`;

        return new NextResponse(pdfBytes, {
            status: 200,
            headers: {
                'Content-Type': 'application/pdf',
                'Content-Disposition': contentDisposition,
                // Expose Content-Disposition AND provide X-Filename as a reliable fallback.
                // Browsers block Content-Disposition from fetch() by default — ACAO-E fixes this.
                'Access-Control-Expose-Headers': 'Content-Disposition, X-Filename',
                'X-Filename': cleanFilename,
            },
        });
    } catch (err: any) {
        console.error('[proxy/report/generate-pdf]', err.message);
        return NextResponse.json(
            { error: 'Proxy error', detail: err.message },
            { status: 503 }
        );
    }
}
