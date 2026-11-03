package com.anish.analyzer

import android.app.Activity
import android.os.Bundle
import android.content.Intent
import android.net.Uri
import android.widget.*
import java.security.MessageDigest

class MainActivity : Activity() {
    private val pickCode = 42
    private lateinit var output: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 28, 24, 24)
        }
        val title = TextView(this).apply {
            text = "CH3ATGPT Analyzer"
            textSize = 24f
        }
        val note = TextView(this).apply {
            text = "Pilih berkas ELF/APK untuk memeriksa metadata dan mengambil teks yang terbaca. Aplikasi tidak menjalankan berkas yang dianalisis."
            textSize = 14f
        }
        val button = Button(this).apply {
            text = "Pilih berkas"
            setOnClickListener {
                val i = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                    type = "*/*"
                    addCategory(Intent.CATEGORY_OPENABLE)
                }
                startActivityForResult(i, pickCode)
            }
        }
        output = TextView(this).apply {
            textSize = 12f
            setTextIsSelectable(true)
        }
        val scroll = ScrollView(this).apply { addView(output) }
        layout.addView(title)
        layout.addView(note)
        layout.addView(button)
        layout.addView(scroll, LinearLayout.LayoutParams(-1, 0, 1f))
        setContentView(layout)
    }

    @Deprecated("Deprecated in Android but retained for broad compatibility")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != pickCode || resultCode != Activity.RESULT_OK) return
        val uri: Uri = data?.data ?: return
        try {
            contentResolver.openInputStream(uri)?.use { stream ->
                val bytes = stream.readBytes()
                output.text = analyze(bytes)
            } ?: run { output.text = "Berkas tidak dapat dibaca." }
        } catch (e: Exception) {
            output.text = "Gagal membaca: ${e.message}"
        }
    }

    private fun analyze(b: ByteArray): String {
        val sha = MessageDigest.getInstance("SHA-256").digest(b)
            .joinToString("") { "%02x".format(it) }
        val elf = b.size >= 64 && b[0] == 0x7f.toByte() &&
            b[1] == 'E'.code.toByte() && b[2] == 'L'.code.toByte() &&
            b[3] == 'F'.code.toByte()
        val sb = StringBuilder()
        sb.appendLine("Ukuran: ${b.size} byte")
        sb.appendLine("SHA-256: $sha")
        sb.appendLine("Format ELF: ${if (elf) "Ya" else "Tidak terdeteksi"}")
        if (elf) {
            sb.appendLine("Kelas: ${if (b[4].toInt() == 2) "64-bit" else "32-bit/unknown"}")
            sb.appendLine("Endian: ${if (b[5].toInt() == 1) "Little endian" else "Big endian/unknown"}")
            val machine = (b[18].toInt() and 255) or ((b[19].toInt() and 255) shl 8)
            sb.appendLine("Arsitektur ELF: ${if (machine == 183) "AArch64 / ARM64" else "Kode mesin $machine"}")
        }
        val strings = mutableListOf<String>()
        val current = StringBuilder()
        for (byte in b) {
            val c = byte.toInt() and 255
            if (c in 32..126) current.append(c.toChar())
            else {
                if (current.length >= 5) strings.add(current.toString())
                current.setLength(0)
            }
        }
        if (current.length >= 5) strings.add(current.toString())
        sb.appendLine()
        sb.appendLine("=== TEKS TERBACA (maks. 500 baris) ===")
        strings.distinct().take(500).forEach { sb.appendLine(it) }
        sb.appendLine()
        sb.appendLine("Catatan: teks acak/terenkripsi tidak bisa dipulihkan tanpa mengetahui algoritma dan kunci yang benar.")
        return sb.toString()
    }
}
