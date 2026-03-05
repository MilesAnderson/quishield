package com.cs433.quishield

import androidx.fragment.app.DialogFragment
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import android.widget.Button

//Below imports allow for url activation
import android.content.Intent
import android.net.Uri

/* this file contains the code that opens up a dialogue after a QR code is detected.
    A user can then decide to click the cancel button dismissing the dialogue, or click the visit link button taking them to the url in the QR.*/


class ScanResultDialogFragment : DialogFragment() {

    companion object {

        fun newInstance(
            url: String,
            summary: String
        ): ScanResultDialogFragment {
            val fragment = ScanResultDialogFragment()
            val args = Bundle()
            args.putString("URL", url)
            args.putString("SUMMARY", summary)
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
        val summary = arguments?.getString("SUMMARY")
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
        val urlText =
            view.findViewById<TextView>(R.id.urlText)
        val summaryText =
            view.findViewById<TextView>(R.id.summaryText)
        urlText.text = url
        summaryText.text = summary
        return view
    }
}