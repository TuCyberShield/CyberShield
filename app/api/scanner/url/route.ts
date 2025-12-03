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

        // Simulate URL analysis
        const suspiciousPatterns = [
            'bit.ly',
            'tinyurl',
            'login',
            'verify',
            'account',
            'secure',
            'update',
            'confirm',
        ]

        const url = input.toLowerCase()
        const threats: string[] = []
        let riskLevel = 'low'

        // Check for suspicious patterns
        suspiciousPatterns.forEach(pattern => {
            if (url.includes(pattern)) {
                threats.push(`Patrón sospechoso detectado: "${pattern}"`)
            }
        })

        // Check for phishing indicators
        if (!url.startsWith('https://')) {
            threats.push('URL no utiliza HTTPS - conexión insegura')
        }

        if (url.includes('@')) {
            threats.push('URL contiene "@" - posible intento de engaño')
            riskLevel = 'high'
        }

        if (url.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)) {
            threats.push('URL utiliza dirección IP en lugar de dominio')
            riskLevel = 'medium'
        }

        // Determine risk level
        if (threats.length > 3) {
            riskLevel = 'high'
        } else if (threats.length > 1) {
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
            recommendations.push('No acceder a este enlace')
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
