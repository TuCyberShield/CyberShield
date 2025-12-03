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
        const { input, fileType, fileSize } = body

        if (!input) {
            return NextResponse.json({ error: 'Archivo requerido' }, { status: 400 })
        }

        // Simulate invoice analysis
        const filename = input.toLowerCase()
        const threats: string[] = []
        let riskLevel = 'low'

        // Check file size (simulated - in real app this would be actual file)
        if (fileSize && fileSize > 10 * 1024 * 1024) { // 10MB
            threats.push('Archivo excede el tamaño recomendado (>10MB)')
            riskLevel = 'medium'
        }

        // Check file type
        const validTypes = ['application/pdf', 'image/png', 'image/jpeg', 'image/jpg']
        if (fileType && !validTypes.includes(fileType)) {
            threats.push('Tipo de archivo no válido o sospechoso')
            riskLevel = 'high'
        }

        // Check for suspicious filename patterns
        const suspiciousPatterns = [
            '.exe',
            '.bat',
            '.scr',
            '.com',
            'urgent',
            'immediate',
            'action required',
            'overdue',
        ]

        suspiciousPatterns.forEach(pattern => {
            if (filename.includes(pattern)) {
                threats.push(`Patrón sospechoso en nombre: "${pattern}"`)
                if (pattern.startsWith('.')) {
                    riskLevel = 'high'
                } else {
                    riskLevel = riskLevel === 'low' ? 'medium' : riskLevel
                }
            }
        })

        // Check for double extensions
        const extensionCount = (filename.match(/\./g) || []).length
        if (extensionCount > 1) {
            threats.push('Archivo con múltiples extensiones detectado')
            riskLevel = 'high'
        }

        // Simulate OCR/content analysis keywords
        const fraudKeywords = ['wire transfer', 'bitcoin', 'cryptocurrency', 'urgent payment']
        const hasKeywords = fraudKeywords.some(keyword => filename.includes(keyword.replace(' ', '_')))

        if (hasKeywords) {
            threats.push('Contenido sospechoso de fraude financiero detectado')
            riskLevel = 'high'
        }

        // Store analysis result
        if (threats.length > 0) {
            await prisma.threat.create({
                data: {
                    userId: payload.userId,
                    type: 'invoice_fraud',
                    origin: input,
                    description: threats.join(', '),
                    severity: riskLevel,
                    status: riskLevel === 'high' ? 'quarantine' : 'monitoring',
                },
            })
        }

        const recommendations = []
        if (riskLevel === 'high') {
            recommendations.push('NO PROCESAR este documento')
            recommendations.push('Contactar al remitente por canal oficial')
            recommendations.push('Reportar como posible fraude')
            recommendations.push('Verificar autenticidad con el emisor')
        } else if (riskLevel === 'medium') {
            recommendations.push('Verificar remitente antes de procesar')
            recommendations.push('Confirmar detalles de pago por teléfono')
            recommendations.push('Revisar números de cuenta cuidadosamente')
        } else {
            recommendations.push('Factura parece legítima')
            recommendations.push('Verificar datos de pago estándar')
            recommendations.push('Archivar copia de seguridad')
        }

        return NextResponse.json({
            riskLevel,
            threats,
            recommendations,
            analyzed: true,
            fileInfo: {
                name: input,
                type: fileType || 'unknown',
                size: fileSize ? `${(fileSize / 1024).toFixed(2)} KB` : 'unknown'
            }
        })
    } catch (error) {
        console.error('Invoice scan error:', error)
        return NextResponse.json(
            { error: 'Error al analizar factura' },
            { status: 500 }
        )
    }
}
