import { PDFDocument, rgb, StandardFonts } from 'pdf-lib'
import fs from 'fs'
import path from 'path'

export default async function handler(req, res) {
  try {
    // Example AI output (replace with Groq response)
    const aiText =
      req.body?.text ||
      'This PDF was generated safely on Vercel using pdf-lib.'

    // Create PDF
    const pdfDoc = await PDFDocument.create()

    // Use standard font (Vercel-safe)
    const font = await pdfDoc.embedFont(StandardFonts.Helvetica)

    const page = pdfDoc.addPage([595, 842]) // A4
    const { height } = page.getSize()

    // Title
    page.drawText('AI Generated PDF', {
      x: 50,
      y: height - 80,
      size: 28,
      font,
      color: rgb(0.15, 0.35, 0.85),
    })

    // Body text
    page.drawText(aiText, {
      x: 50,
      y: height - 140,
      size: 14,
      font,
      color: rgb(0, 0, 0),
      maxWidth: 500,
      lineHeight: 18,
    })

    // Generate bytes
    const pdfBytes = await pdfDoc.save()

    // IMPORTANT: no file system writes
    res.setHeader('Content-Type', 'application/pdf')
    res.setHeader(
      'Content-Disposition',
      'inline; filename="ai.pdf"'
    )

    return res.send(Buffer.from(pdfBytes))
  } catch (err) {
    console.error(err)
    return res.status(500).json({ error: 'PDF generation failed' })
  }
}
