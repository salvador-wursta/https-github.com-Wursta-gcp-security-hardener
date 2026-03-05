'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
    const router = useRouter();

    // Basic JIT state (will be replaced by context/store later)
    const [jitActive, setJitActive] = useState(false);
    const [sessionTime, setSessionTime] = useState(0);

    return (
        <div className="min-h-screen bg-gray-50 flex flex-col font-sans text-gray-900">
            {/* HEADER */}
            <header className="bg-white border-b border-gray-200 sticky top-0 z-50">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
                    <a href="/" className="flex items-center gap-3 hover:opacity-80 transition-opacity">
                        {/* Logo Placeholder */}
                        <div className="w-8 h-8 bg-blue-600 rounded-md flex items-center justify-center text-white font-bold">
                            G
                        </div>
                        <span className="text-xl font-bold tracking-tight text-gray-900">
                            GCP Security <span className="text-blue-600">Hardener</span>
                        </span>
                    </a>

                    <div className="flex items-center gap-4">
                        {jitActive ? (
                            <div className="flex items-center gap-2 bg-green-50 px-3 py-1.5 rounded-full border border-green-200">
                                <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span>
                                <span className="text-sm font-medium text-green-700">JIT Session Active</span>
                                <span className="text-xs text-green-600 ml-1">({Math.floor(sessionTime / 60)}m left)</span>
                            </div>
                        ) : (
                            <button
                                onClick={() => window.alert("Open JIT Upload Modal")}
                                className="text-sm font-medium text-gray-600 hover:text-blue-600 transition-colors flex items-center gap-1"
                            >
                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11.536 9.636a1.003 1.003 0 00-.454-.28l-2.668-.777M8 2a6 6 0 016 6v0a6 6 0 01-6 6v0a4 4 0 110-8h0z" /></svg>
                                Upload Credentials
                            </button>
                        )}
                    </div>
                </div>
            </header>

            {/* MAIN CONTENT */}
            <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
                {children}
            </main>

            {/* FOOTER */}
            <footer className="bg-white border-t border-gray-200 mt-auto">
                <div className="max-w-7xl mx-auto px-4 py-6 sm:px-6 lg:px-8">
                    <div className="flex justify-between items-center text-xs text-gray-500">
                        <p>© 2026 GCP Security Hardener. V2.0 Major Update.</p>
                        <div className="flex gap-4">
                            <Link href="/privileges" className="hover:text-gray-900">Privilege Info</Link>
                            <Link href="/support" className="hover:text-gray-900">Support</Link>
                        </div>
                    </div>
                </div>
            </footer>
        </div>
    );
}
