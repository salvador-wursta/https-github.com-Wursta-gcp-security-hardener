import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import './globals.css'
import { ClientProvider } from '../context/ClientContext'


const inter = Inter({ subsets: ['latin'], variable: '--font-inter' })

export const metadata: Metadata = {
  title: 'GCP Security Hardener - Protect Your Cloud',
  description: 'Automated security hardening for Google Cloud Platform tenants',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className={`${inter.className} ${inter.variable} font-sans`}>
        <ClientProvider>
          {children}
        </ClientProvider>
      </body>
    </html>
  )
}
