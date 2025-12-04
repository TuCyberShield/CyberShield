/** @type {import('next').NextConfig} */
const nextConfig = {
    // Server Actions are stable in Next.js 14+, no experimental flag needed
    reactStrictMode: true,
    swcMinify: true,
    experimental: {
        // Skip static generation for pages that use useSearchParams
        skipTrailingSlashRedirect: true,
    },
    // Force these pages to be server-rendered
    async rewrites() {
        return []
    },
}

module.exports = nextConfig
