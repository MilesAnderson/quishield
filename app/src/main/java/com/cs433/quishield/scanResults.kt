package com.cs433.quishield

import androidx.fragment.app.DialogFragment
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import android.widget.Button
import android.widget.ProgressBar

//Below imports allow for url activation
import android.content.Intent
import android.net.Uri


/* this file contains the code that opens up a dialogue after a QR code is detected.
    A user can then decide to click the cancel button dismissing the dialogue, or click the visit link button taking them to the url in the QR.*/

// this is to help the url display cleaner
private fun breakUrl(url: String): String {
    return url.replace("/", "/\u200B")
        .replace("?", "?\u200B")
        .replace("&", "&\u200B")
        .replace("=", "=\u200B")
}

class ScanResultDialogFragment : DialogFragment() {

    // this gets rid of rectangle so it can be rounded
    override fun onStart() {
        super.onStart()
        dialog?.window?.setBackgroundDrawableResource(android.R.color.transparent)
        dialog?.window?.setLayout(
            (resources.displayMetrics.widthPixels * 0.85).toInt(),
            ViewGroup.LayoutParams.WRAP_CONTENT
        )
    }
    companion object {

        fun newInstance(
            url: String,
            assessment: String,
            score: Int,
            reasons: String
        ): ScanResultDialogFragment {
            val fragment = ScanResultDialogFragment()
            val args = Bundle()
            args.putString("URL", url)
            args.putString("ASSESSMENT", assessment)
            args.putInt("SCORE", score)
            args.putString("REASONS", reasons)
            fragment.arguments = args
            return fragment
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val view = inflater.inflate(
            R.layout.scan_results,
            container,
            false
        )
        val url = arguments?.getString("URL")
        val assessment = arguments?.getString("ASSESSMENT")
        // defaults to -1 (error)
        val score = arguments?.getInt("SCORE", -1)
        val reasons = arguments?.getString("REASONS")

//        val summary = arguments?.getString("SUMMARY")



        val urlText =
            view.findViewById<TextView>(R.id.urlText)
        urlText.text = breakUrl(url ?: "")

        val scoreText =
            view.findViewById<TextView>(R.id.scoreText)
        scoreText.text = if (score == -1) {
            "Error computing risk level!"
        } else {
            "Risk Level: $score/100"
        }

        val assessmentText =
            view.findViewById<TextView>(R.id.assessmentText)
        assessmentText.text = assessment

        // color change depending on evaluation
        when (assessment) {
            "🚫 Dangerous" -> assessmentText.setTextColor(
                resources.getColor(android.R.color.holo_red_dark))
            "⚠️ Suspicious" -> assessmentText.setTextColor(
                resources.getColor(android.R.color.holo_orange_dark))
            "✅ Low Risk" -> assessmentText.setTextColor(
                resources.getColor(android.R.color.holo_green_dark))
        }

//        scoreText.setTextColor(assessmentText.currentTextColor)


        val riskBar = view.findViewById<ProgressBar>(R.id.riskMeter)
        // bar showing level of risk
        score?.let {
            riskBar.progress = it

            val color = when {
                it <= 30 -> android.graphics.Color.parseColor("#2E7D32")
                it <= 70 -> android.graphics.Color.parseColor("#F9A825")
                else -> android.graphics.Color.parseColor("#C62828")
            }

            riskBar.progressDrawable.setTint(color)
        }

        val reasonsText =
            view.findViewById<TextView>(R.id.reasonsText)
        reasonsText.text = reasons

//        val summaryText =
//            view.findViewById<TextView>(R.id.summaryText)
//        summaryText.text = summary

        val cancelButton = view.findViewById<Button>(R.id.cancelButton)
        cancelButton.setOnClickListener {
            dismiss()
        }
        val visitButton = view.findViewById<Button>(R.id.visitButton)
        visitButton.setOnClickListener {
            url?.let { UrlId: String ->
                val intent = Intent( Intent.ACTION_VIEW, Uri.parse(UrlId))
                startActivity(intent)
            }
            dismiss()
        }

        return view
    }
}