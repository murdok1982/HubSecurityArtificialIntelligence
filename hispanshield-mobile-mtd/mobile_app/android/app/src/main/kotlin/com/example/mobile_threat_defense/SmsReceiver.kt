package com.example.mobile_threat_defense

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import android.telephony.SmsMessage
import io.flutter.plugin.common.MethodChannel

class SmsReceiver : BroadcastReceiver() {
    
    companion object {
        const val CHANNEL = "com.mtd/sms"
        var methodChannel: MethodChannel? = null
    }
    
    override fun onReceive(context: Context?, intent: Intent?) {
        if (intent?.action == Telephony.Sms.Intents.SMS_RECEIVED_ACTION) {
            val bundle = intent.extras
            if (bundle != null) {
                val pdus = bundle.get("pdus") as Array<*>
                val messages = arrayOfNulls<SmsMessage>(pdus.size)
                
                for (i in pdus.indices) {
                    messages[i] = SmsMessage.createFromPdu(pdus[i] as ByteArray)
                }
                
                if (messages.isNotEmpty()) {
                    val sender = messages[0]?.originatingAddress ?: ""
                    val messageBody = StringBuilder()
                    
                    for (message in messages) {
                        messageBody.append(message?.messageBody)
                    }
                    
                    // Send to Flutter
                    val smsData = mapOf(
                        "sender" to sender,
                        "message" to messageBody.toString(),
                        "timestamp" to System.currentTimeMillis()
                    )
                    
                    methodChannel?.invokeMethod("onSmsReceived", smsData)
                }
            }
        }
    }
}
