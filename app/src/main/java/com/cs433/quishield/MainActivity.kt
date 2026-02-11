package com.cs433.quishield

//Android lifecycle + UI imports
import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.activity.result.contract.ActivityResultContracts
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
    private lateinit var uploadImgButton: Button
    private lateinit var resultText: TextView
    private lateinit var qrImageView: ImageView

    // store if current object is bitmap or uri
    private var currentBitmap: Bitmap? = null
    private var currentImageUri: Uri? = null

    /**
     * List of QR code images stored in res/drawable for testing
     */
    private val samples = listOf(
        R.drawable.qr_example1,
        R.drawable.qr_example2,
        R.drawable.qr_example3
    )
    private var index = 0
    private val backend = BackendClient("http://10.0.2.2:3000")

    // virus total
    private val virusTotal = VirusTotalClient("ea1850218e6d748bfdf87f57ea28b485444351c5071fb25bc739bedf6d8d6695")

    // upload image
    private val pickImageLauncher = registerForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        uri?.let {
            qrImageView.setImageURI(it)
            resultText.text = "Image uploaded from camera roll"
            currentImageUri = it
            currentBitmap = null
        }
    }

    // scan image
    private val cameraLauncher = registerForActivityResult(
        ActivityResultContracts.TakePicturePreview()
    ) { bitmap: Bitmap? ->
        bitmap?.let {
            qrImageView.setImageBitmap(it)
            resultText.text = "Image captured from camera"
            currentBitmap = it
            currentImageUri = null
        }
    }


    override fun onCreate(savedInstanceState: Bundle?) {

        // splash screen
        installSplashScreen()

        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)

        qrImageView = findViewById(R.id.qrImageView)
        resultText = findViewById(R.id.resultText)
        uploadImgButton = findViewById(R.id.upload_img)

        // buttons
        val prevBtn = findViewById<Button>(R.id.prevBtn)
        val nextBtn = findViewById<Button>(R.id.nextBtn)
        val uploadImgButton = findViewById<Button>(R.id.upload_img)
        val decodeBtn = findViewById<Button>(R.id.decodeBtn)
        val scanBtn = findViewById<Button>(R.id.scanBtn)


        // display current image object
        fun showCurrent() {
            qrImageView.setImageResource(samples[index])
            resultText.text = "Showing sample ${index + 1} / ${samples.size}"
            currentBitmap = null
            currentImageUri = null
        }

        // prev
        prevBtn.setOnClickListener {
            index = (index - 1 + samples.size) % samples.size
            showCurrent()
        }

        // next
        nextBtn.setOnClickListener {
            index = (index + 1) % samples.size
            showCurrent()
        }

        // upload button: launches photo gallery
        uploadImgButton.setOnClickListener {
            pickImageLauncher.launch("image/*")
        }

        // scan button: launches camera if applicable
        scanBtn.setOnClickListener {
            if (hasCameraPermission()) {
                cameraLauncher.launch(null)
            } else {
                requestPermissions(
                    arrayOf(android.Manifest.permission.CAMERA),
                    100
                )
            }
        }

        // updated version of decode that works for scan or upload & uses virustotal
        decodeBtn.setOnClickListener {
            val decoded = when {
                currentBitmap != null -> decodeQrFromBitmap(currentBitmap!!)
                currentImageUri != null -> decodeQrFromUri(currentImageUri!!)
                else -> null
            }

            if (decoded == null) {
                resultText.text = "No QR code found"
            } else {
                sendToVirusTotal(decoded)
            }
        }

        /**
         * Decode Button:
         * 1. Attempts to decode the QR code from the displayed image
         * 2. If decoding succeeds, send the result to the backend
         * 3. Otherwise, notify the user
         */
//        decodeBtn.setOnClickListener {
//            val currentUri = selectedImageUri
//            if (currentUri != null) {
//                val text = decodeQrFromUri(currentUri)
//                if (text == null) {
//                    resultText.text = "No QR code found in selected image"
//                    } else {
//                    sendToBackend(text)
//                    }
//                } else {
//                resultText.text = "Please upload an image first"
//            }
//        }


        showCurrent()

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == 100 && grantResults.isNotEmpty()
            && grantResults[0] == android.content.pm.PackageManager.PERMISSION_GRANTED) {
            cameraLauncher.launch(null)
        }
    }

    /**
     * sendToBackend
     *
     * Sends the decoded QR content to the backend server for security analysis.
     * Performs a basic frontend safety check before making the network request.
     */
//    private fun sendToBackend(decodeText: String) {
//        val trimmed = decodeText.trim()
//        if (!(trimmed.startsWith("http://") || trimmed.startsWith("https://"))){
//            resultText.text = "Blocked (unsupported scheme): $trimmed"
//            return
//        }
//
//        resultText.text = "Checking safety..."
//
//        /**
//         * Network rquests are performed on a background thread (IO dispatcher).
//         * UI updates must occur on the main thread.
//         */
//        CoroutineScope(Dispatchers.IO).launch {
//            try {
//                val json = backend.scanUrl(trimmed)
//                withContext(Dispatchers.Main){
//                    resultText.text = "Backed result:\n$json"
//                }
//            } catch (e: Exception) {
//                withContext(Dispatchers.Main) {
//                    resultText.text = "Backend error: ${e.message}"
//                }
//            }
//        }
//    }

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
//    private fun decodeQrFromUri(uri: Uri): String? {
//        val bitmap: Bitmap = decodeUriToBitmap(uri) ?: return null
//        val pixels = IntArray(bitmap.width * bitmap.height)
//        bitmap.getPixels(
//            pixels,
//            0,
//            bitmap.width,
//            0,
//            0,
//            bitmap.width,
//            bitmap.height
//        )
//
//        val source = RGBLuminanceSource(bitmap.width, bitmap.height, pixels)
//        val binaryBitmap = BinaryBitmap(HybridBinarizer(source))
//
//        return try {
//            MultiFormatReader().decode(binaryBitmap).text
//        } catch (e: Exception) {
//            null
//        }
//    }

    // turn uri to bitmap and then decode
    private fun decodeQrFromUri(uri: Uri): String? {
        val bitmap = decodeUriToBitmap(uri) ?: return null
        return decodeQrFromBitmap(bitmap)
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

    // decode bitmap
    private fun decodeQrFromBitmap(bitmap: Bitmap): String? {
        val pixels = IntArray(bitmap.width * bitmap.height)
        bitmap.getPixels(pixels, 0, bitmap.width, 0, 0, bitmap.width, bitmap.height)

        val source = RGBLuminanceSource(bitmap.width, bitmap.height, pixels)
        val binaryBitmap = BinaryBitmap(HybridBinarizer(source))

        return try {
            MultiFormatReader().decode(binaryBitmap).text
        } catch (e: Exception) {
            null
        }
    }

    // check if device has camera hardware
    private fun hasCameraPermission(): Boolean {
        return checkSelfPermission(android.Manifest.permission.CAMERA) ==
                android.content.pm.PackageManager.PERMISSION_GRANTED
    }

    // send decoded link to virus total
    private fun sendToVirusTotal(url: String) {
        val trimmed = url.trim()
        if (!(trimmed.startsWith("http://") || trimmed.startsWith("https://"))) {
            resultText.text = "Blocked (unsupported scheme): $trimmed"
            return
        }

        resultText.text = "Checking safety..."

        CoroutineScope(Dispatchers.IO).launch {
            try {
                val analysis = virusTotal.scanUrl(trimmed)
                val stats = analysis.data.attributes.lastAnalysisStats
                withContext(Dispatchers.Main) {
                    resultText.text = "VirusTotal analysis:\n" +
                            "Malicious: ${stats["malicious"] ?: 0}, " +
                            "Suspicious: ${stats["suspicious"] ?: 0}, " +
                            "Harmless: ${stats["harmless"] ?: 0}"
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    resultText.text = "VirusTotal error: ${e.message}"
                }
            }
        }
    }
}