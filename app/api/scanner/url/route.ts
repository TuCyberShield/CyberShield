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
            // URL shorteners
            'bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',

            // Login/account (English)
            'login', 'signin', 'sign-in', 'log-in', 'verify', 'account', 'auth',
            'secure', 'security', 'update', 'confirm', 'authentication', 'check',
            'validation', 'portal', 'access', 'admin', 'sysadmin',

            // Login/account (Spanish)
            'iniciar-sesion', 'iniciosesion', 'verificar', 'verifica',
            'cuenta', 'cuentas', 'seguro', 'segura', 'seguras', 'actualizar',
            'confirmar', 'autenticacion', 'validar', 'validacion', 'gestion',

            // Banking/finance (English)
            'banking', 'bank', 'paypal', 'amazon', 'netflix', 'microsoft',
            'apple', 'icloud', 'google', 'facebook', 'instagram', 'wallet',
            'payment', 'transfer', 'invoice', 'billing',

            // Banking/finance (Spanish)
            'banco', 'bancaria', 'bancario', 'financiero', 'credito', 'debito',
            'tarjeta', 'billetera', 'cartera', 'pago', 'pagos', 'transferencia',
            'factura', 'facturacion', 'proveedor', 'cliente', 'clientebancario',

            // Urgency (English)
            'password', 'suspended', 'locked', 'unusual', 'activity',
            'urgent', 'immediate', 'action', 'required', 'expire', 'expires',
            'alert', 'warning', 'notice', 'blocked', 'limited',

            // Urgency (Spanish)
            'contraseña', 'suspendido', 'bloqueado', 'urgente', 'inmediato',
            'accion', 'requerido', 'alerta', 'aviso', 'advertencia', 'expira',

            // Government/Official (Spanish)
            'sunat', 'gob-pe', 'gobierno', 'fiscal', 'tributaria', 'tributario',
            'notificacion', 'descarga',

            // Shipping/Logistics
            'dhl', 'ups', 'fedex', 'tracking', 'entrega', 'envio', 'envios',
            'delivery', 'shipping', 'logistica', 'seguimiento',

            // Corporate/Business
            'corporativo', 'intranet', 'empresa', 'mailcorporativo',
            'office365', 'microsoft365', 'ms365', 'm365',

            // Generic suspicious
            'online', 'web', 'portal', 'acceso', 'cliente', 'customer',
            'proteccion', 'protection', 'servicio', 'service',
            'soporte', 'support', 'help', 'ayuda',

            // File/Document related
            'documentos', 'archivos', 'files', 'comprobantes', 'reportes',
            'invoice', 'factura', 'descarga', 'download',

            // Identity verification
            'identidad', 'identity', 'mi-identidad',
        ]

        const url = input.toLowerCase()
        const threats: string[] = []
        let riskScore = 0

        // Check for suspicious patterns (each adds 6 points)
        suspiciousPatterns.forEach(pattern => {
            if (url.includes(pattern)) {
                threats.push(`Patrón sospechoso: "${pattern}"`)
                riskScore += 6
            }
        })

        // Check for phishing indicators
        if (!url.startsWith('https://')) {
            threats.push('⚠️ NO usa HTTPS - conexión insegura')
            riskScore += 20
        }

        // Check for @ symbol (CRITICAL)
        if (url.includes('@')) {
            threats.push('🚨 Contiene "@" - ALTO riesgo de phishing')
            riskScore += 40
        }

        // Check for IP address (CRITICAL)
        if (url.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)) {
            threats.push('🚨 Usa dirección IP - muy sospechoso')
            riskScore += 35
        }

        // Check for suspicious TLDs
        const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.zip', '.review', '.info', '.net', '.org']
        const foundTLD = suspiciousTLDs.find(tld => url.includes(tld))
        if (foundTLD) {
            threats.push(`⚠️ Extensión sospechosa: ${foundTLD}`)
            riskScore += 22
        }

        // Check for dangerous file extensions in URL
        const dangerousExtensions = ['.exe', '.bat', '.cmd', '.scr', '.vbs', '.zip', '.rar', '.cab', '.msi']
        dangerousExtensions.forEach(ext => {
            if (url.includes(ext)) {
                threats.push(`🚨 Archivo ejecutable sospechoso: ${ext}`)
                riskScore += 35
            }
        })

        // Check for excessive subdomains
        const domainMatch = url.match(/https?:\/\/([^\/]+)/)
        if (domainMatch) {
            const domain = domainMatch[1]
            const subdomains = domain.split('.').length - 2
            if (subdomains > 3) {
                threats.push(`⚠️ Múltiples subdominios (${subdomains})`)
                riskScore += 18
            }
        }

        // Check for typosquatting and homographs
        const typosquattingPatterns = [
            'paypa1', 'paypai', 'g00gle', 'googIe', 'arnazon', 'amazom',
            'mlcrosoft', 'microsof', 'micros0ft', 'app1e', 'appie',
            'netfl1x', 'facebo0k', 'faceb00k'
        ]
        typosquattingPatterns.forEach(typo => {
            if (url.includes(typo)) {
                threats.push(`🚨 TYPOSQUATTING detectado: "${typo}"`)
                riskScore += 40
            }
        })

        // Check for URL encoding
        if (url.includes('%') && url.match(/%[0-9a-f]{2}/i)) {
            threats.push('⚠️ Caracteres codificados (ofuscación)')
            riskScore += 18
        }

        // Check for excessive length
        if (url.length > 150) {
            threats.push(`⚠️ URL muy larga (${url.length} caracteres)`)
            riskScore += 12
        }

        // Check for multiple dashes (common in phishing)
        const dashCount = (url.match(/-/g) || []).length
        if (dashCount > 3) {
            threats.push(`⚠️ Múltiples guiones (${dashCount})`)
            riskScore += 10
        }

        // Check for numbers mixed with letters (homographs)
        if (url.match(/[a-z]+\d+[a-z]+/) || url.match(/\d+[a-z]+\d+/)) {
            threats.push('⚠️ Números mezclados con letras')
            riskScore += 12
        }

        // Check for government impersonation (non-.gob.pe domains)
        if ((url.includes('sunat') || url.includes('gob') || url.includes('gobierno')) && !url.includes('.gob.pe')) {
            threats.push('🚨 Posible suplantación de entidad gubernamental')
            riskScore += 35
        }

        // Determine risk level (LOWERED THRESHOLDS)
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
            recommendations.push('Verificar el remitente')
        } else if (riskLevel === 'medium') {
            recommendations.push('Proceder con EXTREMA precaución')
            recommendations.push('Verificar legitimidad del sitio')
            recommendations.push('No ingresar datos personales')
        } else {
            recommendations.push('URL parece segura')
            recommendations.push('Mantener precaución general')
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
