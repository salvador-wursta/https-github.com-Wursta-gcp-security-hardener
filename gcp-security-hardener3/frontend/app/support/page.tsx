'use client';

import React, { useState, useMemo } from 'react';
import DashboardLayout from '@/components/DashboardLayout';
import StandardHeader from '@/components/StandardHeader';
import { useRouter } from 'next/navigation';
import { Search, FileText, ChevronRight, BookOpen, AlertTriangle, Code, Terminal, Shield, File } from 'lucide-react';
import { DOCS_DATA } from './docs_data';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

// Robust Markdown Renderer
const MarkdownView = ({ content }: { content: string }) => {
    return (
        <div className="prose prose-blue max-w-none prose-headings:font-bold prose-a:text-blue-600 prose-img:rounded-xl shadow-none">
            <ReactMarkdown
                remarkPlugins={[remarkGfm]}
                components={{
                    // Override specific elements if needed
                    table: ({ node, ...props }) => <div className="overflow-x-auto my-4 border rounded-lg"><table className="w-full text-sm text-left" {...props} /></div>,
                    thead: ({ node, ...props }) => <thead className="bg-gray-50 text-gray-700 uppercase" {...props} />,
                    th: ({ node, ...props }) => <th className="px-6 py-3 font-semibold border-b" {...props} />,
                    td: ({ node, ...props }) => <td className="px-6 py-4 border-b whitespace-nowrap" {...props} />,
                    pre: ({ node, ...props }) => <pre className="bg-slate-900 text-slate-50 p-4 rounded-lg overflow-x-auto my-4" {...props} />,
                    code: ({ node, className, children, ...props }) => {
                        const match = /language-(\w+)/.exec(className || '')
                        const isInline = !match && !className?.includes('language-');
                        return isInline
                            ? <code className="bg-gray-100 text-pink-600 px-1.5 py-0.5 rounded text-sm font-mono" {...props}>{children}</code>
                            : <code className={className} {...props}>{children}</code>
                    }
                }}
            >
                {content}
            </ReactMarkdown>
        </div>
    );
};

export default function SupportPage() {
    const router = useRouter();
    const [selectedDoc, setSelectedDoc] = useState<keyof typeof DOCS_DATA>('RISK_CATALOG'); // Default to Risk Catalog
    const [searchQuery, setSearchQuery] = useState('');

    // Filter docs based on search
    const filteredDocs = useMemo(() => {
        if (!searchQuery) return Object.keys(DOCS_DATA);

        const lowered = searchQuery.toLowerCase();
        return Object.keys(DOCS_DATA).filter(key => {
            const doc = DOCS_DATA[key as keyof typeof DOCS_DATA];
            return doc.title.toLowerCase().includes(lowered) || doc.content.toLowerCase().includes(lowered);
        });
    }, [searchQuery]);

    // Icon mapping helper
    const getIconForDoc = (key: string) => {
        const map: Record<string, React.ReactNode> = {
            "RISK_CATALOG": <AlertTriangle className="w-4 h-4" />,
            "README": <BookOpen className="w-4 h-4" />,
            "SECURE_CODE": <Code className="w-4 h-4" />,
            "SETUP_GUIDE": <Terminal className="w-4 h-4" />,
            "WINDOWS_GUIDE": <Terminal className="w-4 h-4" />,
            "GCP_HARDENING_OVERVIEW": <Shield className="w-4 h-4" />,
            "PRIVILEGE_MODEL": <Shield className="w-4 h-4" />,
            "TECHNICAL_REFERENCE": <FileText className="w-4 h-4" />
        };
        return map[key] || <File className="w-4 h-4" />;
    };

    return (
        <DashboardLayout>
            <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden h-[calc(100vh-140px)] flex flex-col">
                <StandardHeader
                    title="Support & Documentation"
                    subtitle="Technical references, capabilities catalog, and security guides."
                    onBack={() => router.push('/')}
                    backLabel="Back to Dashboard"
                />

                <div className="flex flex-1 overflow-hidden">
                    {/* Left Sidebar - File List */}
                    <div className="w-80 border-r border-gray-200 bg-gray-50 flex flex-col">
                        <div className="p-4 border-b border-gray-200 bg-white">
                            <div className="relative">
                                <Search className="absolute left-3 top-2.5 w-4 h-4 text-gray-400" />
                                <input
                                    type="text"
                                    placeholder="Search documentation..."
                                    className="w-full pl-9 pr-4 py-2 text-sm border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                                    value={searchQuery}
                                    onChange={(e) => setSearchQuery(e.target.value)}
                                />
                            </div>
                        </div>

                        <div className="flex-1 overflow-y-auto p-2 space-y-1">
                            {filteredDocs.map((key) => {
                                const docKey = key as keyof typeof DOCS_DATA;
                                const isActive = selectedDoc === docKey;

                                return (
                                    <button
                                        key={key}
                                        onClick={() => setSelectedDoc(docKey)}
                                        className={`w-full text-left px-3 py-3 rounded-lg flex items-center gap-3 transition-all ${isActive
                                            ? 'bg-white shadow-sm ring-1 ring-gray-200 text-blue-600'
                                            : 'text-gray-600 hover:bg-gray-100 hover:text-gray-900'
                                            }`}
                                    >
                                        <div className={`flex-shrink-0 ${isActive ? 'text-blue-500' : 'text-gray-400'}`}>
                                            {getIconForDoc(key)}
                                        </div>
                                        <span className="text-sm font-medium truncate flex-1">{DOCS_DATA[docKey].title}</span>
                                        {isActive && <ChevronRight className="w-3.5 h-3.5 text-blue-400" />}
                                    </button>
                                );
                            })}

                            {filteredDocs.length === 0 && (
                                <div className="text-center py-8 px-4 text-gray-400 text-sm">
                                    No documents found matching "{searchQuery}"
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Right Panel - Content */}
                    <div className="flex-1 overflow-y-auto bg-white p-8 md:p-12">
                        <div className="max-w-4xl mx-auto">
                            <div className="mb-8 pb-6 border-b border-gray-100">
                                <h1 className="text-3xl font-bold text-gray-900 mb-2">
                                    {DOCS_DATA[selectedDoc].title}
                                </h1>
                                <div className="flex items-center gap-2 text-sm text-gray-500">
                                    {getIconForDoc(selectedDoc as string)}
                                    <span>Documentation / {selectedDoc}</span>
                                </div>
                            </div>

                            <MarkdownView content={DOCS_DATA[selectedDoc].content} />
                        </div>
                    </div>
                </div>
            </div>
        </DashboardLayout>
    );
}
