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
            return NextResponse.json({ error: 'Contenido de email requerido' }, { status: 400 })
        }

        // Simulate email analysis
        const suspiciousKeywords = [
            'urgent',
            'verify your account',
            'click here',
            'winner',
            'congratulations',
            'prize',
            'act now',
            'limited time',
            'suspended',
            'unusual activity',
        ]

        const emailContent = input.toLowerCase()
        const threats: string[] = []
        let riskLevel = 'low'

        // Check for suspicious keywords
        suspiciousKeywords.forEach(keyword => {
            if (emailContent.includes(keyword)) {
                threats.push(`Palabra clave sospechosa: "${keyword}"`)
            }
        })

        // Check for excessive links
        const linkCount = (emailContent.match(/http/gi) || []).length
        if (linkCount > 3) {
            threats.push(`Número elevado de enlaces (${linkCount})`)
            riskLevel = 'medium'
        }

        // Check for spoofing indicators
        if (emailContent.includes('paypal') && !emailContent.includes('@paypal.com')) {
            threats.push('Posible suplantación de identidad (spoofing)')
            riskLevel = 'high'
        }

        // Determine risk level based on threats
        if (threats.length > 3) {
            riskLevel = 'high'
        } else if (threats.length > 1) {
            riskLevel = 'medium'
        }

        // Store email analysis
        await prisma.email.create({
            data: {
                userId: payload.userId,
                sender: 'unknown@example.com',
                subject: 'Análisis de contenido',
                content: input.substring(0, 500),
                analyzed: true,
                riskLevel,
            },
        })

        // Create threat if high risk
        if (riskLevel === 'high') {
            await prisma.threat.create({
                data: {
                    userId: payload.userId,
                    type: 'email_phishing',
                    origin: 'email_content',
                    description: threats.join(', '),
                    severity: riskLevel,
                    status: 'blocked',
                },
            })
        }

        const recommendations = []
        if (riskLevel === 'high') {
            recommendations.push('No responder al correo')
            recommendations.push('No hacer clic en enlaces')
            recommendations.push('Marcar como spam/phishing')
            recommendations.push('Eliminar el correo')
        } else if (riskLevel === 'medium') {
            recommendations.push('Verificar remitente')
            recommendations.push('No proporcionar información personal')
        } else {
            recommendations.push('Email parece legítimo')
            recommendations.push('Mantener precaución general')
        }

        return NextResponse.json({
            riskLevel,
            threats,
            recommendations,
            analyzed: true,
        })
    } catch (error) {
        console.error('Email scan error:', error)
        return NextResponse.json(
            { error: 'Error al analizar email' },
            { status: 500 }
        )
    }
}
