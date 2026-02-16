package com.example.mobile_threat_defense

import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity: FlutterActivity() {
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        
        // Setup SMS channel
        val smsChannel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, SmsReceiver.CHANNEL)
        SmsReceiver.methodChannel = smsChannel
        
        // Setup Call channel
        val callChannel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CallReceiver.CHANNEL)
        CallReceiver.methodChannel = callChannel
        
        // Setup App Scanner channel
        val scannerChannel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "com.mtd/scanner")
        scannerChannel.setMethodCallHandler { call, result ->
            when (call.method) {
                "scanInstalledApps" -> {
                    val apps = scanInstalledApps()
                    result.success(apps)
                }
                else -> result.notImplemented()
            }
        }
    }
    
    private fun scanInstalledApps(): List<Map<String, Any>> {
        val pm = packageManager
        val packages = pm.getInstalledPackages(android.content.pm.PackageManager.GET_PERMISSIONS)
        val appsList = mutableListOf<Map<String, Any>>()
        
        for (packageInfo in packages) {
            val appInfo = hashMapOf<String, Any>(
                "packageName" to packageInfo.packageName,
                "versionCode" to packageInfo.versionCode.toLong(),
                "versionName" to (packageInfo.versionName ?: "unknown"),
                "permissions" to (packageInfo.requestedPermissions?.toList() ?: emptyList()),
                "installerPackage" to (pm.getInstallerPackageName(packageInfo.packageName) ?: "unknown"),
                "firstInstallTime" to packageInfo.firstInstallTime
            )
            appsList.add(appInfo)
        }
        
        return appsList
    }
}
