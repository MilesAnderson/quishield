package com.cs433.quishield

//Android lifecycle + UI imports
import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import android.widget.Button
import android.widget.ImageView
import android.widget.TextView
import android.net.Uri
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen


// Bitmap handling (used to decode QR images)
import android.graphics.Bitmap
import android.graphics.BitmapFactory

// ZXing imports for QR code decoding
import com.google.zxing.BinaryBitmap
import com.google.zxing.MultiFormatReader
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer

// Kotlin coroutines (used for backend networking)
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext


/**
 * Main Activity serves as the main entry point of the app.
 * Responsibilities:
 * 1. Decode QR codes using ZXing
 * 2. Send decoded URLs to the backend for security analysis
 * 3. Display the backend's response to the user
 */
class MainActivity : AppCompatActivity() {

    /**
     * List of QR code images stored in res/drawable for testing
     */

    private lateinit var uploadImgButton: Button
    private var selectedImageUri: Uri? = null

    private val pickImageLauncher = registerForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        selectedImageUri     = uri
        findViewById<ImageView>(R.id.qrImageView).setImageURI(uri)
        findViewById<TextView>(R.id.resultText).text = "Image loaded from Gallery"
    }


    private val samples = listOf(
        R.drawable.qr_example1,
        R.drawable.qr_example2,
        R.drawable.qr_example3
    )
    private var index = 0
    private val backend = BackendClient("http://10.0.2.2:3000")
    private lateinit var resultText: TextView

    override fun onCreate(savedInstanceState: Bundle?) {

        // splash screen
        installSplashScreen()

        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)

        val qrImageView = findViewById<ImageView>(R.id.qrImageView)
        resultText = findViewById(R.id.resultText)

        val prevBtn = findViewById<Button>(R.id.prevBtn)
        val nextBtn = findViewById<Button>(R.id.nextBtn)
        val decodeBtn = findViewById<Button>(R.id.decodeBtn)

        uploadImgButton = findViewById(R.id.upload_img)
        uploadImgButton.setOnClickListener {
            pickImageLauncher.launch("image/*")
        }

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

        /**
         * Decode Button:
         * 1. Attempts to decode the QR code from the displayed image
         * 2. If decoding succeeds, send the result to the backend
         * 3. Otherwise, notify the user
         */
        decodeBtn.setOnClickListener {
            val currentUri = selectedImageUri
            if (currentUri != null) {
                val text = decodeQrFromUri(currentUri)
                if (text == null) {
                    resultText.text = "No QR code found in selected image"
                    } else {
                    sendToBackend(text)
                    }
                } else {
                resultText.text = "Please upload an image first"
            }
        }

        showCurrent()

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }
    }

    /**
     * sendToBackend
     *
     * Sends the decoded QR content to the backend server for security analysis.
     * Performs a basic frontend safety check before making the network request.
     */
    private fun sendToBackend(decodeText: String) {
        val trimmed = decodeText.trim()
        if (!(trimmed.startsWith("http://") || trimmed.startsWith("https://"))){
            resultText.text = "Blocked (unsupported scheme): $trimmed"
            return
        }

        resultText.text = "Checking safety..."

        /**
         * Network rquests are performed on a background thread (IO dispatcher).
         * UI updates must occur on the main thread.
         */
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val json = backend.scanUrl(trimmed)
                withContext(Dispatchers.Main){
                    resultText.text = "Backed result:\n$json"
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    resultText.text = "Backend error: ${e.message}"
                }
            }
        }
    }

    /**
     * decodeQrFromDrawable
     *
     * Uses the AXing library to decode a QR code from a drawable resource.
     * Steps:
     * 1. Concert drawable into a Bitmap
     * 2. Extract raw pixel data
     * 3. Convert pixels into a luminance source
     * 4. Decode using ZXing's MultiFormatReader
     */
    private fun decodeQrFromUri(uri: Uri): String? {
        val bitmap: Bitmap = decodeUriToBitmap(uri) ?: return null
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

/*  below function converts image uri to bitmap
First converts uri through input stream, then decodes the stream in to the bitmap. Content resolver method used from android developers guide*/
    private fun decodeUriToBitmap(uri: Uri): Bitmap? {
        return try {
            val inputStream = contentResolver.openInputStream(uri)
            val bitmap = BitmapFactory.decodeStream(inputStream)
            inputStream?.close()
            bitmap
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }
}