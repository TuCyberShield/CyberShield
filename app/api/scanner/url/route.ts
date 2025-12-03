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

        // Enhanced URL analysis with VERY sensitive phishing detection
        const suspiciousPatterns = [
            // URL shorteners (very common in phishing)
            'bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',

            // Login/account related (English)
            'login', 'signin', 'sign-in', 'log-in', 'verify', 'account',
            'secure', 'security', 'update', 'confirm', 'authentication', 'auth',

            // Login/account related (Spanish)
            'iniciar-sesion', 'inicio-sesion', 'iniciosesion', 'verificar',
            'cuenta', 'cuentas', 'seguro', 'segura', 'seguras', 'actualizar',
            'confirmar', 'autenticacion', 'validar', 'validacion',

            // Banking/finance keywords (English)
            'banking', 'bank', 'paypal', 'pay-pal', 'amazon', 'netflix', 'microsoft',
            'apple', 'icloud', 'google', 'facebook', 'instagram', 'twitter',
            'chase', 'wellsfargo', 'citibank', 'bankofamerica', 'wallet',

            // Banking/finance keywords (Spanish)
            'banco', 'banca', 'bancaria', 'bancario', 'financiero', 'financiera',
            'credito', 'debito', 'tarjeta', 'billetera', 'cartera',

            // Urgent/pressure words (English)
            'password', 'suspended', 'locked', 'unusual', 'activity',
            'urgent', 'immediate', 'action', 'required', 'expire', 'expires',
            'alert', 'warning', 'notice', 'blocked', 'limited',

            // Urgent/pressure words (Spanish)
            'contraseña', 'suspendido', 'suspendida', 'bloqueado', 'bloqueada',
            'urgente', 'inmediato', 'inmediata', 'accion', 'requerido', 'requerida',
            'alerta', 'aviso', 'advertencia', 'expira', 'caduca',

            // Common phishing tactics
            'crypto', 'bitcoin', 'prize', 'winner', 'claim',
            'refund', 'tax', 'irs', 'revenue', 'support', 'help',
            'premio', 'ganador', 'reclamar', 'reembolso', 'soporte', 'ayuda',

            // Suspicious generic words
            'online', 'web', 'portal', 'acceso', 'access', 'cliente', 'customer',
            'proteccion', 'protection', 'servicio', 'service'
        ]

        const url = input.toLowerCase()
        const threats: string[] = []
        let riskScore = 0 // 0-100 risk score

        // Check for suspicious patterns (each adds 6 points)
        suspiciousPatterns.forEach(pattern => {
            if (url.includes(pattern)) {
                threats.push(`Patrón sospechoso detectado: "${pattern}"`)
                riskScore += 6
            }
        })

        // Check for phishing indicators
        if (!url.startsWith('https://')) {
            threats.push('⚠️ URL no utiliza HTTPS - conexión insegura')
            riskScore += 20
        }

        // Check for @ symbol (CRITICAL - often used to disguise URLs)
        if (url.includes('@')) {
            threats.push('🚨 URL contiene "@" - ALTO riesgo de phishing')
            riskScore += 40
        }

        // Check for IP address instead of domain (CRITICAL)
        if (url.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)) {
            threats.push('🚨 URL utiliza dirección IP - muy sospechoso')
            riskScore += 35
        }

        // Check for suspicious TLDs (high risk extensions)
        const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.zip', '.review', '.info']
        if (suspiciousTLDs.some(tld => url.includes(tld))) {
            threats.push('⚠️ Dominio usa extensión de alto riesgo')
            riskScore += 25
        }

        // Check for excessive subdomains
        const domainMatch = url.match(/https?:\/\/([^\/]+)/)
        if (domainMatch) {
            const domain = domainMatch[1]
            const subdomains = domain.split('.').length - 2
            if (subdomains > 3) {
                threats.push(`⚠️ Número excesivo de subdominios (${subdomains})`)
                riskScore += 20
            }
        }

        // Check for typosquatting (CRITICAL - common misspellings)
        const typosquattingPatterns = {
            'paypa1': 'paypal',
            'paypai': 'paypal',
            'g00gle': 'google',
            'googIe': 'google',
            'arnazon': 'amazon',
            'amazom': 'amazon',
            'mlcrosoft': 'microsoft',
            'microsof': 'microsoft',
            'app1e': 'apple',
            'appie': 'apple',
            'netfl1x': 'netflix',
            'facebo0k': 'facebook',
        }
        Object.entries(typosquattingPatterns).forEach(([typo, real]) => {
            if (url.includes(typo)) {
                threats.push(`🚨 TYPOSQUATTING: "${typo}" (imitando "${real}")`)
                riskScore += 40
            }
        })

        // Check for URL encoding (often used to hide malicious URLs)
        if (url.includes('%') && url.match(/%[0-9a-f]{2}/i)) {
            threats.push('⚠️ URL contiene caracteres codificados (posible ofuscación)')
            riskScore += 18
        }

        // Check for excessive length (phishing URLs are often very long)
        if (url.length > 150) {
            threats.push(`⚠️ URL excesivamente larga (${url.length} caracteres)`)
            riskScore += 12
        }

        // Check for multiple dashes (common in phishing domains)
        const dashCount = (url.match(/-/g) || []).length
        if (dashCount > 3) {
            threats.push(`⚠️ Múltiples guiones en URL (${dashCount}) - patrón sospechoso`)
            riskScore += 10
        }

        // Check for numbers in domain (often used in phishing)
        if (url.match(/[a-z]+\d+[a-z]+/)) {
            threats.push('⚠️ Números mezclados con letras - patrón sospechoso')
            riskScore += 12
        }

        // Determine risk level based on score (LOWERED THRESHOLDS)
        let riskLevel = 'low'
        if (riskScore >= 25) {
            riskLevel = 'high'
        } else if (riskScore >= 15) {
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
