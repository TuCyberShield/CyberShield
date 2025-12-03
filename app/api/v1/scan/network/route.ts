import { NextRequest, NextResponse } from 'next/server'
import { verifyApiKey, checkRateLimit } from '@/lib/api-auth'
import { prisma } from '@/lib/db'

export async function POST(request: NextRequest) {
    try {
        // Verify API key
        const authResult = await verifyApiKey(request)

        if (!authResult.valid) {
            return NextResponse.json(
                { error: authResult.error },
                { status: 401 }
            )
        }

        // Get API key details for rate limiting
        const apiKey = await prisma.apiKey.findUnique({
            where: { id: authResult.apiKeyId }
        })

        if (!apiKey) {
            return NextResponse.json(
                { error: 'API key not found' },
                { status: 401 }
            )
        }

        // Check rate limit
        const rateLimit = checkRateLimit(apiKey.id, apiKey.rateLimit)

        if (!rateLimit.allowed) {
            return NextResponse.json(
                {
                    error: 'Rate limit exceeded',
                    limit: apiKey.rateLimit,
                    resetTime: new Date(rateLimit.resetTime).toISOString()
                },
                {
                    status: 429,
                    headers: {
                        'X-RateLimit-Limit': apiKey.rateLimit.toString(),
                        'X-RateLimit-Remaining': '0',
                        'X-RateLimit-Reset': rateLimit.resetTime.toString()
                    }
                }
            )
        }

        // Parse request body
        const body = await request.json()
        const { ipAddress, port, protocol = 'TCP' } = body

        if (!ipAddress || !port) {
            return NextResponse.json(
                { error: 'IP address and port are required' },
                { status: 400 }
            )
        }

        // Validate IP address format
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/
        if (!ipRegex.test(ipAddress)) {
            return NextResponse.json({ error: 'Invalid IP address format' }, { status: 400 })
        }

        // Validate octets
        const octets = ipAddress.split('.').map(Number)
        if (octets.some((octet: number) => octet > 255)) {
            return NextResponse.json({ error: 'Invalid IP address' }, { status: 400 })
        }

        // Network analysis logic
        const threats: string[] = []
        let riskScore = 0

        // Check for private IP ranges
        const isPrivate = (
            ipAddress.startsWith('192.168.') ||
            ipAddress.startsWith('10.') ||
            ipAddress.startsWith('172.16.') ||
            ipAddress.startsWith('172.17.') ||
            ipAddress.startsWith('172.18.') ||
            ipAddress.startsWith('172.19.') ||
            ipAddress.startsWith('172.20.') ||
            ipAddress.startsWith('172.21.') ||
            ipAddress.startsWith('172.22.') ||
            ipAddress.startsWith('172.23.') ||
            ipAddress.startsWith('172.24.') ||
            ipAddress.startsWith('172.25.') ||
            ipAddress.startsWith('172.26.') ||
            ipAddress.startsWith('172.27.') ||
            ipAddress.startsWith('172.28.') ||
            ipAddress.startsWith('172.29.') ||
            ipAddress.startsWith('172.30.') ||
            ipAddress.startsWith('172.31.')
        )

        if (isPrivate) {
            threats.push('🔒 Private IP address detected')
            riskScore += 25
        }

        // Check for localhost
        if (ipAddress.startsWith('127.')) {
            threats.push('Localhost/loopback address')
            riskScore += 15
        }

        // Dangerous ports
        const dangerousPorts: Record<number, string> = {
            22: 'SSH - Remote access',
            23: 'Telnet - Insecure remote access',
            3389: 'RDP - Windows Remote Desktop',
            5900: 'VNC - Remote desktop',
            21: 'FTP - File transfer',
            445: 'SMB - Windows file sharing',
            139: 'NetBIOS',
            3306: 'MySQL - Database',
            5432: 'PostgreSQL - Database',
            27017: 'MongoDB - Database',
            1433: 'MS SQL Server',
            6379: 'Redis - Database',
            12345: 'NetBus (Trojan)',
            31337: 'Back Orifice (Trojan)',
            6667: 'IRC - Used by botnets'
        }

        if (dangerousPorts[port]) {
            threats.push(`🚨 Dangerous port: ${dangerousPorts[port]}`)
            riskScore += 30
        }

        // Safe ports (reduce risk)
        const safePorts = [80, 443, 53, 25, 110, 143, 993, 995]
        if (safePorts.includes(port)) {
            threats.push(`✓ Standard port: ${port}`)
            riskScore -= 10
        }

        // High ports
        if (port > 49152) {
            threats.push('High port number (>49152)')
            riskScore += 15
        }

        // Determine risk level
        let riskLevel = 'low'
        let status = 'active'

        if (riskScore >= 40) {
            riskLevel = 'high'
            status = 'blocked'
        } else if (riskScore >= 20) {
            riskLevel = 'medium'
            status = 'monitoring'
        }

        // Store in database
        await prisma.connection.create({
            data: {
                userId: authResult.userId!,
                ipAddress,
                port,
                protocol,
                status,
            }
        })

        if (riskLevel === 'high') {
            await prisma.threat.create({
                data: {
                    userId: authResult.userId!,
                    type: 'network_suspicious',
                    origin: `${ipAddress}:${port}`,
                    description: threats.join(', '),
                    severity: riskLevel,
                    status: 'blocked',
                },
            })
        }

        // Return response with rate limit headers
        return NextResponse.json(
            {
                ipAddress,
                port,
                protocol,
                riskLevel,
                riskScore,
                status,
                threats,
                analyzed: true,
                timestamp: new Date().toISOString()
            },
            {
                headers: {
                    'X-RateLimit-Limit': apiKey.rateLimit.toString(),
                    'X-RateLimit-Remaining': rateLimit.remaining.toString(),
                    'X-RateLimit-Reset': rateLimit.resetTime.toString()
                }
            }
        )
    } catch (error) {
        console.error('API network scan error:', error)
        return NextResponse.json(
            { error: 'Internal server error' },
            { status: 500 }
        )
    }
}
