package com.example.mobile_threat_defense

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.telephony.TelephonyManager
import io.flutter.plugin.common.MethodChannel

class CallReceiver : BroadcastReceiver() {
    
    companion object {
        const val CHANNEL = "com.mtd/call"
        var methodChannel: MethodChannel? = null
        private var lastState = TelephonyManager.CALL_STATE_IDLE
        private var callNumber = ""
        private var callStartTime = 0L
    }
    
    override fun onReceive(context: Context?, intent: Intent?) {
        val state = intent?.getStringExtra(TelephonyManager.EXTRA_STATE)
        val incomingNumber = intent?.getStringExtra(TelephonyManager.EXTRA_INCOMING_NUMBER)
        
        when (state) {
            TelephonyManager.EXTRA_STATE_RINGING -> {
                callNumber = incomingNumber ?: "Unknown"
                val callData = mapOf(
                    "event" to "ringing",
                    "number" to callNumber,
                    "timestamp" to System.currentTimeMillis()
                )
                methodChannel?.invokeMethod("onCallStateChanged", callData)
            }
            
            TelephonyManager.EXTRA_STATE_OFFHOOK -> {
                if (lastState != TelephonyManager.CALL_STATE_RINGING) {
                    callStartTime = System.currentTimeMillis()
                }
            }
            
            TelephonyManager.EXTRA_STATE_IDLE -> {
                if (lastState == TelephonyManager.CALL_STATE_OFFHOOK) {
                    val duration = (System.currentTimeMillis() - callStartTime) / 1000
                    val callData = mapOf(
                        "event" to "ended",
                        "number" to callNumber,
                        "duration" to duration,
                        "timestamp" to System.currentTimeMillis()
                    )
                    methodChannel?.invokeMethod("onCallStateChanged", callData)
                }
            }
        }
        
        lastState = when (state) {
            TelephonyManager.EXTRA_STATE_RINGING -> TelephonyManager.CALL_STATE_RINGING
            TelephonyManager.EXTRA_STATE_OFFHOOK -> TelephonyManager.CALL_STATE_OFFHOOK
            else -> TelephonyManager.CALL_STATE_IDLE
        }
    }
}
