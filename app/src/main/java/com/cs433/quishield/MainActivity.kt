package com.cs433.quishield

import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

//My imports
import android.widget.Button
import android.widget.Toast
import android.widget.ImageView
import android.widget.TextView


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
            resultText.text = "Decoding sample ${index + 1}..."
        }

        showCurrent()

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }
    }
}