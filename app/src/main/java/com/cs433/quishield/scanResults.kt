package com.cs433.quishield

import androidx.fragment.app.DialogFragment
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView

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
        val urlText =
            view.findViewById<TextView>(R.id.urlText)
        val summaryText =
            view.findViewById<TextView>(R.id.summaryText)
        urlText.text = url
        summaryText.text = summary
        return view
    }
}