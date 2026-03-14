// ------------------------ IMPORTS ----------------------------------
// our kt files
package com.cs433.quishield

// Android lifecycle + UI imports
import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import androidx.core.view.WindowCompat
import androidx.core.content.ContextCompat
import androidx.core.text.HtmlCompat
import androidx.lifecycle.lifecycleScope
import android.net.Uri
import android.view.View
import android.util.Log

// widgets
import android.widget.Button
import android.widget.ImageView
import android.widget.TextView
import android.widget.ScrollView
import android.widget.ProgressBar
import androidx.constraintlayout.widget.ConstraintLayout

// Bitmap handling (used to decode QR images)
import android.graphics.Bitmap
import android.graphics.BitmapFactory

// ZXing imports for QR code decoding
import com.google.zxing.BinaryBitmap
import com.google.zxing.MultiFormatReader
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.DecodeHintType
import com.google.zxing.BarcodeFormat

// Kotlin coroutines (used for backend networking)
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
import androidx.camera.core.ImageCapture
import androidx.camera.core.ImageCaptureException
// ------------------------ IMPORTS ----------------------------------


class MainActivity : AppCompatActivity() {
// ---------------------------VARS------------------------------------------
    // main screen
    private lateinit var mainContent: ScrollView
    private lateinit var qrPlaceholder: TextView
    private lateinit var qrImageView: ImageView
    private lateinit var resultText: TextView
    private lateinit var loadingSpinner: ProgressBar

    // camera view overlays
    private lateinit var cameraView: ConstraintLayout
    private lateinit var previewView: PreviewView

    // camera scan stuff
    private var cameraProvider: ProcessCameraProvider? = null
    private var qrDetected = false // track whether we've already captured a frame during this scan session
    private var imageCapture: ImageCapture? = null // store captured CameraX frame

    // store current bitmap
    private var currentBitmap: Bitmap? = null

    // store decoded QR text from the live scan (prevents re-decoding bitmap)
    private var lastScanRawText: String? = null
// --------------------------------VARS------------------------------------------


// --------------------------------VALS------------------------------------------
    // ZXing QR decoder (set to only look for QRs)
    private val qrReader = MultiFormatReader().apply {
        val hints = mapOf(
            DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
            DecodeHintType.TRY_HARDER to true
        )
        setHints(hints)
    }

    // upload image stuff
    private val pickImageLauncher = registerForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        uri?.let {
            val bitmap = decodeUriToBitmap(it)

            if (bitmap != null) {
                currentBitmap = bitmap

                qrImageView.setImageBitmap(bitmap)
                resultText.text = "Image uploaded from camera roll.\nTap DECODE to begin security scan."

            } else {
                resultText.text = "Error processing image."
            }

            // switch from placeholder to real image
            qrImageView.visibility = View.VISIBLE
            qrPlaceholder.visibility = View.GONE
        }
    }

    // virus total
    private val virusTotal = VirusTotalClient(BuildConfig.VT_API_KEY)
// ---------------------------VALS------------------------------------------


// ------------------------CAMERA PERMS-----------------------------------
// check if device has camera hardware/permissions
private fun hasCameraPermission(): Boolean {
    return checkSelfPermission(android.Manifest.permission.CAMERA) ==
            android.content.pm.PackageManager.PERMISSION_GRANTED
}

    // handle camera permission check
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
// ------------------------CAMERA PERMS-----------------------------------


// ---------------------------CAMERA FUNCTIONS------------------------------------------
    /*image scanner - adapted from google's official cameraX sample and ZXing library, see:
    https://developer.android.com/media/camera/camerax/analyze
    https://github.com/zxing/zxing*/
    private inner class QrAnalyzer : ImageAnalysis.Analyzer {
        override fun analyze(image: ImageProxy) {
            if (qrDetected) {
                image.close()
                return
            }
            val buffer = image.planes[0].buffer
            buffer.rewind()
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
                val result = qrReader.decode(binaryBitmap)

                qrDetected = true
                lastScanRawText = result.text

                image.close()

                captureDetectedQr()

                runOnUiThread {
                    mainContent.visibility = View.VISIBLE
                    cameraView.visibility = View.GONE

                    qrImageView.visibility = View.VISIBLE
                    qrPlaceholder.visibility = View.GONE

                    resultText.text = "QR detected. Tap DECODE to analyze."
                }
            } catch (e: Exception) {
                image.close()
            }
        }
    }

    // camera starter also adapted from google developers guide:
    private fun startCamera() {
        val cameraProviderFuture =
            ProcessCameraProvider.getInstance(this)

        cameraProviderFuture.addListener({
            cameraProvider =
                cameraProviderFuture.get()

            val preview = Preview.Builder().build()
            preview.setSurfaceProvider(
                previewView.surfaceProvider
            )

            imageCapture = ImageCapture.Builder().build()

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
                imageCapture,
                imageAnalyzer
            )
        }, ContextCompat.getMainExecutor(this))
    }

    // take picture of detected qr code during scan
    private fun captureDetectedQr() {
        val imageCapture = imageCapture ?: return

        imageCapture.takePicture(
            ContextCompat.getMainExecutor(this),
            object: ImageCapture.OnImageCapturedCallback() {
                override fun onCaptureSuccess(image: ImageProxy) {

                    val bitmap = imageProxyToBitmap(image)

                    runOnUiThread {
                        currentBitmap = bitmap

                        qrImageView.setImageBitmap(bitmap)
                        qrImageView.visibility = View.VISIBLE
                    }

                    image.close()
                    cameraProvider?.unbindAll()
                }

                override fun onError(exception: ImageCaptureException) {
                    Log.e("QR_CAPTURE", "Image capture failed", exception)
                }
            }
        )
    }

    // convert cameraX YUV frame into bitmap
    private fun imageProxyToBitmap(image: ImageProxy): Bitmap {
        val buffer = image.planes[0].buffer
        val bytes = ByteArray(buffer.remaining())
        buffer.get(bytes)

        return BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
    }
// ---------------------------CAMERA FUNCTIONS-------------------------------------------


// ---------------------------DECODE/EVAL FUNCTIONS------------------------------------------
    /*  below function converts image uri to bitmap (handles uploaded images)
First converts uri through input stream, then decodes the stream in to the bitmap. Content resolver method used from android developers guide*/
    private fun decodeUriToBitmap(uri: Uri): Bitmap? {
        return try {
            val inputStream = contentResolver.openInputStream(uri)

            val options = BitmapFactory.Options().apply {
                inSampleSize = 2
                inPreferredConfig = Bitmap.Config.RGB_565
            }

            val bitmap = BitmapFactory.decodeStream(inputStream, null, options)
            inputStream?.close()
            bitmap

        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    // decode bitmap w/ multiformatreader (set for QR codes)
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

    // convert QR text into URL
    private fun extractUrl(raw: String): String? {
        val regex = Regex("""https?://[^\s]+""")
        return regex.find(raw)?.value
    }

    // send decoded link to virus total
    private fun evaluateRisk(url: String) {
        loadingSpinner.visibility = View.VISIBLE
        val trimmed = url.trim()
        if (!(trimmed.startsWith("http://") || trimmed.startsWith("https://"))) {
            loadingSpinner.visibility = View.GONE
            resultText.text = "Blocked: only http/https links are supported.\n\n$trimmed"
            return
        }

        resultText.text = "Securely analyzing QR code...\nThis may take a few seconds."

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val report = virusTotal.scanUrlReport(trimmed)
                Log.d("VT_DEBUG", virusTotal.formatReportForDebug(report))

                val assessment = RiskAssessment.assess(report, trimmed)

                // separate into final assessment, score, and justification
                val level = assessment.level
                val score = assessment.score
                val reasons = assessment.reasons.joinToString("\n") { "• $it." }

                withContext(Dispatchers.Main) {
                    loadingSpinner.visibility = View.GONE
                    val dialog = ScanResultDialogFragment.newInstance(trimmed, level, score, reasons)
                    dialog.show(supportFragmentManager, "ScanResult")
                    resultText.text = HtmlCompat.fromHtml(
                        getString(R.string.completed_resulttext),
                        HtmlCompat.FROM_HTML_MODE_LEGACY)
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    loadingSpinner.visibility = View.GONE
                    resultText.text = "VirusTotal error: ${e.message}"
                }
            }
        }
    }
// ---------------------------DECODE/EVAL FUNCTIONS------------------------------------------


// ---------------------------OVERRIDE FUNCTIONS------------------------------------------
    // on create display stuff
    override fun onCreate(savedInstanceState: Bundle?) {

        // splash screen
        installSplashScreen()

        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)

        // this is for making some words bold/colored in the instructions (HTML)
        val qrInstructions = findViewById<TextView>(R.id.qrInstructions)
        qrInstructions.text = HtmlCompat.fromHtml(
            getString(R.string.qr_instruction),
            HtmlCompat.FROM_HTML_MODE_LEGACY
        )
        //-------------------------VARS--------------------------------------
        // -----------------main screen----------------------
        mainContent = findViewById(R.id.mainContent)

        // display
        qrImageView = findViewById(R.id.qrImageView)
        qrPlaceholder = findViewById(R.id.qrPlaceholder)

        // buttons
        val decodeBtn = findViewById<Button>(R.id.decodeBtn)
        val scanBtn = findViewById<Button>(R.id.scanBtn)
        val exitScanBtn = findViewById<Button>(R.id.exitScanBtn)
        val uploadBtn = findViewById<Button>(R.id.uploadBtn)

        // footer/outputs
        resultText = findViewById(R.id.resultText)
        resultText.text = HtmlCompat.fromHtml(
            getString(R.string.default_resulttext),
            HtmlCompat.FROM_HTML_MODE_LEGACY
        )

        // progress spinner
        loadingSpinner = findViewById(R.id.loadingSpinner)
        // -----------------main screen----------------------

        // -----------------scan screen----------------------
        // camera scan overlay
        cameraView = findViewById(R.id.cameraView)
        previewView = findViewById(R.id.previewView)
        // -----------------scan screen----------------------
        //-------------------------VARS--------------------------------------


        // ------------------------BUTTONS-------------------------------------
        // scan button: lets user capture picture using cameraX
        scanBtn.setOnClickListener {
            if (hasCameraPermission()) {
                lastScanRawText = null
                qrDetected = false

                mainContent.visibility = View.GONE
                cameraView.visibility = View.VISIBLE

                startCamera()
            } else {
                // get camera perms
                requestPermissions(
                    arrayOf(android.Manifest.permission.CAMERA),
                    100
                )
            }
        }

        // cancel scan (return to main view)
        exitScanBtn.setOnClickListener {
            cameraView.visibility = View.GONE
            mainContent.visibility = View.VISIBLE

            cameraProvider?.unbindAll()
        }

        // upload button: launches photo gallery
        uploadBtn.setOnClickListener {
            lastScanRawText = null
            pickImageLauncher.launch("image/*")
        }

        // decode button: calls decode functions on bitmap or loads scanned url, then sends to risk evaluator
        decodeBtn.setOnClickListener {
            val decoded = lastScanRawText ?: currentBitmap?.let { decodeQrFromBitmap(it) }

            if (decoded == null) {
                resultText.text = "No QR code found."
            } else {
                val url = extractUrl(decoded)
                if (url != null) {
                    evaluateRisk(url)
                } else {
                    resultText.text = "No valid URL found."
                }
            }
        }
        // ------------------------BUTTONS-------------------------------------

        // fits display to screen size
        WindowCompat.setDecorFitsSystemWindows(window, true)
    }

    // on destroy crash handling
    override fun onDestroy() {
        super.onDestroy()
        cameraProvider?.unbindAll()
    }
// ---------------------------OVERRIDE FUNCTIONS------------------------------------------
}
