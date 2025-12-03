import { NextRequest, NextResponse } from 'next/server'
import { prisma } from '@/lib/db'
import { verifyToken } from '@/lib/auth'

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
        const { input } = body

        if (!input) {
            return NextResponse.json({ error: 'URL requerida' }, { status: 400 })
        }

        // Enhanced URL analysis with comprehensive phishing detection
        const suspiciousPatterns = [
            'bit.ly', 'tinyurl', 'goo.gl', 't.co', // URL shorteners
            'login', 'signin', 'verify', 'account', 'secure', 'update', 'confirm',
            'banking', 'paypal', 'amazon', 'netflix', 'microsoft', 'apple',
            'password', 'suspended', 'locked', 'unusual', 'activity',
            'urgent', 'immediate', 'action', 'required', 'expire',
        ]

        const url = input.toLowerCase()
        const threats: string[] = []
        let riskScore = 0 // 0-100 risk score

        // Check for suspicious patterns (each adds 10 points)
        suspiciousPatterns.forEach(pattern => {
            if (url.includes(pattern)) {
                threats.push(`Patrón sospechoso detectado: "${pattern}"`)
                riskScore += 10
            }
        })

        // Check for phishing indicators
        if (!url.startsWith('https://')) {
            threats.push('URL no utiliza HTTPS - conexión insegura')
            riskScore += 15
        }

        // Check for @ symbol (often used to disguise URLs)
        if (url.includes('@')) {
            threats.push('URL contiene "@" - posible intento de engaño')
            riskScore += 30
        }

        // Check for IP address instead of domain
        if (url.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)) {
            threats.push('URL utiliza dirección IP en lugar de dominio')
            riskScore += 25
        }

        // Check for suspicious TLDs
        const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click']
        if (suspiciousTLDs.some(tld => url.includes(tld))) {
            threats.push('Dominio usa extensión de alto riesgo')
            riskScore += 20
        }

        // Check for excessive subdomains
        const domainMatch = url.match(/https?:\/\/([^\/]+)/)
        if (domainMatch) {
            const domain = domainMatch[1]
            const subdomains = domain.split('.').length - 2
            if (subdomains > 3) {
                threats.push(`Número excesivo de subdominios (${subdomains})`)
                riskScore += 15
            }
        }

        // Check for typosquatting (common misspellings)
        const typosquattingPatterns = {
            'paypa1': 'paypal',
            'g00gle': 'google',
            'arnazon': 'amazon',
            'mlcrosoft': 'microsoft',
            'app1e': 'apple',
        }
        Object.entries(typosquattingPatterns).forEach(([typo, real]) => {
            if (url.includes(typo)) {
                threats.push(`Posible typosquatting: "${typo}" (imitando "${real}")`)
                riskScore += 35
            }
        })

        // Check for URL encoding (often used to hide malicious URLs)
        if (url.includes('%') && url.match(/%[0-9a-f]{2}/i)) {
            threats.push('URL contiene caracteres codificados (posible ofuscación)')
            riskScore += 15
        }

        // Check for excessive length (phishing URLs are often very long)
        if (url.length > 150) {
            threats.push(`URL excesivamente larga (${url.length} caracteres)`)
            riskScore += 10
        }

        // Determine risk level based on score
        let riskLevel = 'low'
        if (riskScore >= 60) {
            riskLevel = 'high'
        } else if (riskScore >= 30) {
            riskLevel = 'medium'
        }

        // Store threat if detected
        if (threats.length > 0) {
            await prisma.threat.create({
                data: {
                    userId: payload.userId,
                    type: 'url_phishing',
                    origin: input,
                    description: threats.join(', '),
                    severity: riskLevel,
                    status: riskLevel === 'high' ? 'blocked' : 'monitoring',
                },
            })
        }

        const recommendations = []
        if (riskLevel === 'high') {
            recommendations.push('NO acceder a este enlace')
            recommendations.push('Reportar como phishing')
            recommendations.push('Verificar el remitente del mensaje')
        } else if (riskLevel === 'medium') {
            recommendations.push('Proceder con precaución')
            recommendations.push('Verificar la legitimidad del sitio')
        } else {
            recommendations.push('URL parece segura')
            recommendations.push('Mantener actualizado el antivirus')
        }

        return NextResponse.json({
            riskLevel,
            threats,
            recommendations,
            analyzed: true,
        })
    } catch (error) {
        console.error('URL scan error:', error)
        return NextResponse.json(
            { error: 'Error al analizar URL' },
            { status: 500 }
        )
    }
}
