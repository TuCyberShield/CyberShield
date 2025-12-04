import { NextRequest, NextResponse } from 'next/server'
import { prisma } from '@/lib/db'
import { verifyToken } from '@/lib/auth'
import { analyzeConnection, checkKnownConnection } from '@/lib/network-threats'
import { getThreatIntelligence, combineThreatScores } from '@/lib/threat-intelligence'

export async function POST(request: NextRequest) {
    try {
        const authHeader = request.headers.get('authorization')

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return NextResponse.json({ error: 'No autorizado' }, { status: 401 })
        }

        const token = authHeader.substring(7)
        const payload = verifyToken(token)

        if (!payload) {
            return NextResponse.json({ error: 'Token inválido' }, { status: 401 })
        }

        const body = await request.json()
        const { ipAddress, port, protocol = 'TCP' } = body

        if (!ipAddress) {
            return NextResponse.json({ error: 'IP address requerida' }, { status: 400 })
        }

        if (!port || port < 1 || port > 65535) {
            return NextResponse.json({ error: 'Puerto inválido (1-65535)' }, { status: 400 })
        }

        // Validate IP format
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/
        if (!ipRegex.test(ipAddress)) {
            return NextResponse.json({ error: 'Formato de IP inválido' }, { status: 400 })
        }

        // Check each octet is valid (0-255)
        const octets = ipAddress.split('.').map(Number)
        if (octets.some((octet: number) => octet > 255)) {
            return NextResponse.json({ error: 'IP address inválida' }, { status: 400 })
        }

        // Use the comprehensive threat analysis
        const analysis = analyzeConnection(ipAddress, port)
        const knownConnection = checkKnownConnection(ipAddress, port)

        let threats = [...analysis.threats]
        let riskScore = 0

        // Map risk level to numeric score
        switch (analysis.riskLevel) {
            case 'critical':
                riskScore = 100
                break
            case 'high':
                riskScore = 70
                break
            case 'warning':
                riskScore = 40
                break
            case 'safe':
                riskScore = 0
                break
        }

        // Additional checks for IP characteristics
        const isPrivateIP =
            (octets[0] === 10) ||
            (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
            (octets[0] === 192 && octets[1] === 168) ||
            (octets[0] === 127)

        if (isPrivateIP && !knownConnection) {
            threats.push('🔒 IP privada detectada')
            if (analysis.riskLevel !== 'safe') {
                riskScore += 15
            }
        }

        // Check for localhost
        if (octets[0] === 127) {
            threats.push('⚠️ Dirección loopback (localhost)')
        }

        // Check for broadcast/multicast
        if (octets[0] >= 224) {
            threats.push('⚠️ Dirección multicast/broadcast')
            riskScore += 10
        }

        // Determine status based on risk level
        let status = 'active'
        let riskLevel: 'low' | 'medium' | 'high' = 'low'

        if (analysis.riskLevel === 'critical') {
            status = 'blocked'
            riskLevel = 'high' // Map to existing database schema
        } else if (analysis.riskLevel === 'high') {
            status = 'blocked'
            riskLevel = 'high'
        } else if (analysis.riskLevel === 'warning') {
            status = 'monitoring'
            riskLevel = 'medium'
        } else {
            status = 'active'
            riskLevel = 'low'
        }

        // Get threat intelligence from AbuseIPDB
        const threatIntel = await getThreatIntelligence(ipAddress)

        // Combine threat intelligence with rule-based analysis
        if (threatIntel) {
            const combined = combineThreatScores(riskScore, threatIntel)
            riskLevel = combined.riskLevel
            riskScore = combined.finalScore

            // Update status based on combined score
            if (riskLevel === 'high') {
                status = 'blocked'
            } else if (riskLevel === 'medium') {
                status = 'monitoring'
            } else {
                status = 'active'
            }

            // Add threat intelligence insights to threats array
            if (threatIntel.totalReports > 0) {
                threats.push(`🌐 ${threatIntel.totalReports} reportes de abuso globales`)
            }
            if (threatIntel.abuseConfidenceScore > 0) {
                threats.push(`📊 Confianza de amenaza: ${threatIntel.abuseConfidenceScore}%`)
            }
            if (threatIntel.isWhitelisted) {
                threats.push(`✅ IP verificada como legítima`)
            }
        }

        // Store in database
        await prisma.connection.create({
            data: {
                userId: payload.userId,
                ipAddress,
                port,
                protocol,
                status,
            },
        })

        // Create threat if high or critical risk
        if (analysis.riskLevel === 'high' || analysis.riskLevel === 'critical') {
            await prisma.threat.create({
                data: {
                    userId: payload.userId,
                    type: 'network_connection',
                    origin: `${ipAddress}:${port}`,
                    description: `${analysis.emoji} ${threats.join(' | ')}`,
                    severity: riskLevel,
                    status: 'blocked',
                },
            })
        }

        const recommendations = analysis.recommendations

        return NextResponse.json({
            riskLevel,
            threats,
            recommendations,
            analyzed: true,
            connectionInfo: {
                ip: ipAddress,
                port,
                protocol,
                status,
                category: analysis.category,
                emoji: analysis.emoji,
                riskScore,
                threatIntelligence: threatIntel ? {
                    provider: threatIntel.provider,
                    abuseConfidenceScore: threatIntel.abuseConfidenceScore,
                    totalReports: threatIntel.totalReports,
                    lastReportedAt: threatIntel.lastReportedAt,
                    isWhitelisted: threatIntel.isWhitelisted,
                    countryCode: threatIntel.countryCode,
                    isp: threatIntel.isp,
                    cached: threatIntel.cached,
                } : null
            }
        })
    } catch (error) {
        console.error('Network scan error:', error)
        return NextResponse.json(
            { error: 'Error al analizar conexión' },
            { status: 500 }
        )
    }
}
