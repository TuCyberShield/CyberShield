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

        // Enhanced invoice analysis with comprehensive fraud detection
        const filename = input.toLowerCase()
        const threats: string[] = []
        let riskScore = 0

        // Check file size (simulated - in real app this would be actual file)
        if (fileSize && fileSize > 10 * 1024 * 1024) { // 10MB
            threats.push('Archivo excede el tamaño recomendado (>10MB)')
            riskScore += 15
        }

        // Check file type - strict validation
        const validTypes = ['application/pdf', 'image/png', 'image/jpeg', 'image/jpg']
        if (fileType && !validTypes.includes(fileType)) {
            threats.push('Tipo de archivo no válido o sospechoso')
            riskScore += 40
        }

        // Check for dangerous executable extensions
        const dangerousExtensions = [
            '.exe', '.bat', '.cmd', '.scr', '.vbs', '.js', '.jar',
            '.com', '.pif', '.msi', '.app', '.deb', '.dmg'
        ]
        dangerousExtensions.forEach(ext => {
            if (filename.includes(ext)) {
                threats.push(`Extensión peligrosa detectada: "${ext}"`)
                riskScore += 50
            }
        })

        // Check for double extensions (common malware technique)
        const extensionCount = (filename.match(/\./g) || []).length
        if (extensionCount > 1) {
            threats.push('Archivo con múltiples extensiones detectado')
            riskScore += 35
        }

        // Check for suspicious filename patterns
        const suspiciousFilePatterns = [
            'urgent', 'urgente', 'immediate', 'inmediato',
            'action required', 'acción requerida', 'overdue', 'vencido',
            'final notice', 'aviso final', 'payment due', 'pago pendiente',
            'invoice_', 'factura_', 'receipt_', 'recibo_'
        ]
        suspiciousFilePatterns.forEach(pattern => {
            if (filename.includes(pattern)) {
                threats.push(`Patrón sospechoso en nombre: "${pattern}"`)
                riskScore += 12
            }
        })

        // Check for fraud-related keywords
        const fraudKeywords = [
            'wire transfer', 'transferencia bancaria', 'bitcoin', 'cryptocurrency',
            'urgent payment', 'pago urgente', 'account update', 'actualización de cuenta',
            'verify payment', 'verificar pago', 'unusual activity', 'actividad inusual'
        ]
        fraudKeywords.forEach(keyword => {
            const normalizedKeyword = keyword.replace(' ', '_')
            if (filename.includes(normalizedKeyword) || filename.includes(keyword)) {
                threats.push(`Contenido sospechoso de fraude: "${keyword}"`)
                riskScore += 25
            }
        })

        // Check for typosquatting in company names
        const typosquattedCompanies = [
            'arnazon', 'paypa1', 'mlcrosoft', 'g00gle', 'app1e',
            'netfl1x', 'spotlfy', 'salesf0rce'
        ]
        typosquattedCompanies.forEach(typo => {
            if (filename.includes(typo)) {
                threats.push(`Posible nombre de empresa falsificado: "${typo}"`)
                riskScore += 30
            }
        })

        // Check for suspicious number patterns (fake invoice numbers)
        const suspiciousNumberPatterns = [
            /\d{10,}/, // Very long numbers
            /0{5,}/, // Many zeros
            /1{5,}/, // Many ones
        ]
        suspiciousNumberPatterns.forEach(pattern => {
            if (pattern.test(filename)) {
                threats.push('Patrón numérico sospechoso en nombre de archivo')
                riskScore += 10
            }
        })

        // Check for obfuscation attempts
        if (filename.includes('_') && filename.split('_').length > 5) {
            threats.push('Nombre de archivo excesivamente complejo (posible ofuscación)')
            riskScore += 15
        }

        // Determine risk level based on score
        let riskLevel = 'low'
        if (riskScore >= 60) {
            riskLevel = 'high'
        } else if (riskScore >= 30) {
            riskLevel = 'medium'
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
            recommendations.push('NO ABRIR ni EJECUTAR este archivo')
            recommendations.push('Contactar al remitente por canal oficial')
            recommendations.push('Reportar como posible fraude')
            recommendations.push('Eliminar el archivo inmediatamente')
        } else if (riskLevel === 'medium') {
            recommendations.push('Verificar remitente antes de abrir')
            recommendations.push('Confirmar detalles de pago por teléfono')
            recommendations.push('Revisar números de cuenta cuidadosamente')
            recommendations.push('Escanear con antivirus antes de abrir')
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
