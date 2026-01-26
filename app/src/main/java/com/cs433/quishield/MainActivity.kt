package com.cs433.quishield

import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import android.widget.Button
import android.widget.ImageView
import android.widget.TextView
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import com.google.zxing.BinaryBitmap
import com.google.zxing.MultiFormatReader
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer

class MainActivity : AppCompatActivity() {
    private val samples = listOf(
        R.drawable.qr_example1,
        R.drawable.qr_example2,
        R.drawable.qr_example3
    )

    private var index = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)

        val qrImageView = findViewById<ImageView>(R.id.qrImageView)
        val resultText = findViewById<TextView>(R.id.resultText)
        val prevBtn = findViewById<Button>(R.id.prevBtn)
        val nextBtn = findViewById<Button>(R.id.nextBtn)
        val decodeBtn = findViewById<Button>(R.id.decodeBtn)

        fun showCurrent() {
            qrImageView.setImageResource(samples[index])
            resultText.text = "Showing sample ${index + 1} / ${samples.size}"
        }

        prevBtn.setOnClickListener {
            index = (index - 1 + samples.size) % samples.size
            showCurrent()
        }

        nextBtn.setOnClickListener {
            index = (index + 1) % samples.size
            showCurrent()
        }

        decodeBtn.setOnClickListener {
            val text = decodeQrFromDrawable(samples[index])
            resultText.text = text ?: "No QR code found"
        }

        showCurrent()

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }
    }
    private fun decodeQrFromDrawable(drawableId: Int): String? {
        val bitmap: Bitmap = BitmapFactory.decodeResource(resources, drawableId)

        val pixels = IntArray(bitmap.width * bitmap.height)
        bitmap.getPixels(
            pixels,
            0,
            bitmap.width,
            0,
            0,
            bitmap.width,
            bitmap.height
        )

        val source = RGBLuminanceSource(bitmap.width, bitmap.height, pixels)
        val binaryBitmap = BinaryBitmap(HybridBinarizer(source))

        return try {
            MultiFormatReader().decode(binaryBitmap).text
        } catch (e: Exception) {
            null
        }
    }
}