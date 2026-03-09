package com.cs433.quishield
//Android lifecycle + UI imports
import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.content.ContextCompat
import androidx.core.text.HtmlCompat

// widgets
import android.widget.Button
import android.widget.ImageView
import android.widget.TextView
import android.widget.ScrollView
import android.widget.FrameLayout
import android.widget.ProgressBar

import android.net.Uri
import android.view.View
import android.util.Log

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

// CameraX (imports for live scanning)
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.CameraSelector
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView


/**
 * Main Activity serves as the main entry point of the app.
 * Responsibilities:
 * 1. Decode QR codes using ZXing
 * 2. Send decoded URLs to the backend for security analysis
 * 3. Display the backend's response to the user
 */
class MainActivity : AppCompatActivity() {
    private lateinit var resultText: TextView
    private lateinit var qrImageView: ImageView
    private lateinit var loadingSpinner: ProgressBar

    // this is for the placeholder QR code before scan/upload
    lateinit var qrPlaceholder: TextView

    // store if current object is bitmap or uri
    private var currentBitmap: Bitmap? = null
    private var currentImageUri: Uri? = null

    /**
     * List of QR code images stored in res/drawable for testing
     */
//    private val samples = listOf(
//        R.drawable.qr_example1,
//        R.drawable.qr_example2,
//        R.drawable.qr_example3
//    )

//    private var index = 0
//    private val backend = BackendClient("http://10.0.2.2:3000")

    private var cameraProvider: ProcessCameraProvider? = null

    // virus total
    private val virusTotal = VirusTotalClient(BuildConfig.VT_API_KEY)

    private val pickImageLauncher = registerForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        uri?.let {
            qrImageView.setImageURI(it)
            // switch from placeholder to real image
            qrImageView.visibility = View.VISIBLE
            qrPlaceholder.visibility = View.GONE

            val qrBox = findViewById<FrameLayout>(R.id.qrBox)
            qrBox.animate().translationZ(12f).setDuration(200).start()

            resultText.text = "Image uploaded from camera roll"
            currentImageUri = it
            currentBitmap = null
        }
    }



    // scan image
    /*
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
    */

    /*image scanner adapted from google's official cameraX sample and ZXing library, see:
    https://developer.android.com/media/camera/camerax/analyze
    https://github.com/zxing/zxing*/

    private inner class QrAnalyzer : ImageAnalysis.Analyzer {
        private var qrDetected = false
        override fun analyze(image: ImageProxy) {
            if (qrDetected) {
                image.close()
                return
            }
            val buffer = image.planes[0].buffer
            val bytes = ByteArray(buffer.remaining())
            buffer.get(bytes)
            val source =
                com.google.zxing.PlanarYUVLuminanceSource(
                    bytes,
                    image.width,
                    image.height,
                    0,
                    0,
                    image.width,
                    image.height,
                    false
                )
            val binaryBitmap =
                BinaryBitmap(HybridBinarizer(source))
            try {
                val result =
                    MultiFormatReader().decode(binaryBitmap)
                qrDetected = true
                val scannedBitmap = imageProxyToBitmap(image)
                runOnUiThread {
                    qrImageView.setImageBitmap(scannedBitmap)
                    qrImageView.visibility = View.VISIBLE
                    qrPlaceholder.visibility = View.GONE

                    val qrBox = findViewById<FrameLayout>(R.id.qrBox)
                    qrBox.animate().translationZ(12f).setDuration(200).start()

                    resultText.text = "QR detected"
                    findViewById<PreviewView>(R.id.previewView).visibility = View.GONE
//                    findViewById<Button>(R.id.closeBtn).visibility = View.GONE
                    // convert text to url before sending to VT
                    val url = extractUrl(result.text)
                    if (url != null) {
                        sendToVirusTotal(url)
                    } else {
                        resultText.text = "No valid URL found in QR"
                    }
                    val cameraProviderFuture = ProcessCameraProvider.getInstance(this@MainActivity)
                    cameraProviderFuture.addListener({
                        val cameraProvider = cameraProviderFuture.get()
                        cameraProvider.unbindAll()
                    }, ContextCompat.getMainExecutor(this@MainActivity))
                }
            } catch (_: Exception) {
            }
            image.close()
        }
    }

    //camera starter also adapted from google developers guide:
    private fun startCamera() {
        val previewView =
            findViewById<PreviewView>(R.id.previewView)
        val cameraProviderFuture =
            ProcessCameraProvider.getInstance(this)
        cameraProviderFuture.addListener({
            cameraProvider =
                cameraProviderFuture.get()
            val preview =
                Preview.Builder().build()
            preview.setSurfaceProvider(
                previewView.surfaceProvider
            )
            val imageAnalyzer =
                ImageAnalysis.Builder()
                    .setBackpressureStrategy(
                        ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST
                    )
                    .build()
                    .also {
                        it.setAnalyzer(
                            ContextCompat.getMainExecutor(this),
                            QrAnalyzer()
                        )
                    }
            val cameraSelector =
                CameraSelector.DEFAULT_BACK_CAMERA
            cameraProvider?.unbindAll()
            cameraProvider?.bindToLifecycle(
                this,
                cameraSelector,
                preview,
                imageAnalyzer
            )
        }, ContextCompat.getMainExecutor(this))
    }

    // this converts scanned QR into clean image
    private fun imageProxyToBitmap(image: ImageProxy): Bitmap {
        val buffer = image.planes[0].buffer
        val bytes = ByteArray(buffer.remaining())
        buffer.get(bytes)

        return BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
    }

    override fun onCreate(savedInstanceState: Bundle?) {

        // splash screen
        installSplashScreen()

        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)

        // main UI overlay
        val mainContent = findViewById<ScrollView>(R.id.mainContent)

        // this is for making some words bold/colored in the instructions (HTML)
        val qrInstructions = findViewById<TextView>(R.id.qrInstructions)
        qrInstructions.text = HtmlCompat.fromHtml(
            getString(R.string.qr_instruction),
            HtmlCompat.FROM_HTML_MODE_LEGACY
        )

        // display
        qrImageView = findViewById(R.id.qrImageView)
        qrPlaceholder = findViewById(R.id.qrPlaceholder)

        // buttons
        val decodeBtn = findViewById<Button>(R.id.decodeBtn)
        val scanBtn = findViewById<Button>(R.id.scanBtn)
        val uploadBtn = findViewById<Button>(R.id.uploadBtn)

        // output
        val resultText = findViewById<TextView>(R.id.resultText)
        resultText.text = HtmlCompat.fromHtml(
            getString(R.string.default_resulttext),
            HtmlCompat.FROM_HTML_MODE_LEGACY
        )

        // progress spinner:
        loadingSpinner = findViewById(R.id.loadingSpinner)

        // camera scan overlay
        val previewView = findViewById<PreviewView>(R.id.previewView)
        val scanFrame = findViewById<View>(R.id.scanFrame)
        val scanText = findViewById<TextView>(R.id.scanText)
        val exitScanBtn = findViewById<Button>(R.id.exitScanBtn)

        // needed four diff rectangles to go around the scanner for some reason
        val dimTop = findViewById<View>(R.id.dimTop)
        val dimBottom = findViewById<View>(R.id.dimBottom)
        val dimLeft = findViewById<View>(R.id.dimLeft)
        val dimRight = findViewById<View>(R.id.dimRight)


        // upload button: launches photo gallery
        uploadBtn.setOnClickListener {
            pickImageLauncher.launch("image/*")
        }

        //updated version of scan button using cameraX:
        scanBtn.setOnClickListener {
            if (hasCameraPermission()) {
                mainContent.visibility = View.GONE

                previewView.visibility = View.VISIBLE
                scanFrame.visibility = View.VISIBLE
                scanText.visibility = View.VISIBLE
                exitScanBtn.visibility = View.VISIBLE

                dimTop.visibility = View.VISIBLE
                dimBottom.visibility = View.VISIBLE
                dimLeft.visibility = View.VISIBLE
                dimRight.visibility = View.VISIBLE

                startCamera()
            } else {
                requestPermissions(
                    arrayOf(android.Manifest.permission.CAMERA),
                    100
                )
            }
        }

        // cancel scan
        exitScanBtn.setOnClickListener {

            previewView.visibility = View.GONE
            scanFrame.visibility = View.GONE
            scanText.visibility = View.GONE
            exitScanBtn.visibility = View.GONE

            dimTop.visibility = View.GONE
            dimBottom.visibility = View.GONE
            dimLeft.visibility = View.GONE
            dimRight.visibility = View.GONE

            mainContent.visibility = View.VISIBLE

            cameraProvider?.unbindAll()
        }

        // updated version of decode that works for scan or upload & uses virustotal
        decodeBtn.setOnClickListener {
            val decoded = when {
                currentBitmap != null -> decodeQrFromBitmap(currentBitmap!!)
                currentImageUri != null -> decodeQrFromUri(currentImageUri!!)
                else -> null
            }

            if (decoded == null) {
                resultText.text = "No QR code found."
            } else {
                val url = extractUrl(decoded)
                if (url != null) {
                    sendToVirusTotal(url)
                } else {
                    resultText.text = "No valid URL found."
                }
            }
        }


//        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
//            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
//            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
//            insets
//        }
        WindowCompat.setDecorFitsSystemWindows(window, true)
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == 100 && grantResults.isNotEmpty()
            && grantResults[0] == android.content.pm.PackageManager.PERMISSION_GRANTED) {
            startCamera()
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


    // convert QR text into URL
    private fun extractUrl(raw: String): String? {
        val regex = Regex("""https?://[^\s]+""")
        return regex.find(raw)?.value
    }


    // send decoded link to virus total
    private fun sendToVirusTotal(url: String) {
        loadingSpinner.visibility = View.VISIBLE
        val trimmed = url.trim()
        if (!(trimmed.startsWith("http://") || trimmed.startsWith("https://"))) {
            resultText.text = "Blocked: only http/https links are supported.\n\n$trimmed"
            return
        }

        resultText.text = "Securely analyzing QR code...\nThis may take a few seconds."

        CoroutineScope(Dispatchers.IO).launch {
            try {
                val report = virusTotal.scanUrlReport(trimmed)
                Log.d("VT_DEBUG", virusTotal.formatReportForDebug(report))

                val assessment = RiskAssessment.assess(report, trimmed)

                // separate into final assessment, score, and justification
                val level = assessment.level
                val score = assessment.score
                val reasons = assessment.reasons.joinToString("\n") { "• $it." }

//                val summary =
//                    "${assessment.level}\n\n" +
//                            assessment.reasons.joinToString("\n") { "• $it" } + "\n\nScanned URL:\n$trimmed"

                withContext(Dispatchers.Main) {
                    loadingSpinner.visibility = View.GONE
                    val dialog = ScanResultDialogFragment.newInstance(trimmed, level, score, reasons)
                    dialog.show(supportFragmentManager, "ScanResult")
                    resultText.text = "Analysis complete ✓ Tap SCAN or UPLOAD to check another QR code."
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    loadingSpinner.visibility = View.GONE
                    resultText.text = "VirusTotal error: ${e.message}"
                }
            }
        }
    }
}