package com.example.mobile_threat_defense

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.File

class AntiTamperingDetector(private val context: Context) {
    
    companion object {
        // Known root binary paths
        private val ROOT_PATHS = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su"
        )
        
        // Known root management apps
        private val ROOT_PACKAGES = arrayOf(
            "com.noshufou.android.su",
            "com.noshufou.android.su.elite",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.topjohnwu.magisk"
        )
    }
    
    /**
     * Check if device is rooted
     */
    fun isDeviceRooted(): Boolean {
        return checkRootBinaries() || 
               checkRootPackages() || 
               checkSuCommand() ||
               checkBuildTags()
    }
    
    /**
     * Check for presence of root binary files
     */
    private fun checkRootBinaries(): Boolean {
        for (path in ROOT_PATHS) {
            if (File(path).exists()) {
                return true
            }
        }
        return false
    }
    
    /**
     * Check for installed root management apps
     */
    private fun checkRootPackages(): Boolean {
        val pm = context.packageManager
        for (packageName in ROOT_PACKAGES) {
            try {
                pm.getPackageInfo(packageName, 0)
                return true  // Package found
            } catch (e: PackageManager.NameNotFoundException) {
                // Package not found, continue
            }
        }
        return false
    }
    
    /**
     * Try to execute 'su' command
     */
    private fun checkSuCommand(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec("su")
            process.destroy()
            true
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Check build tags for test-keys (indicates custom ROM)
     */
    private fun checkBuildTags(): Boolean {
        val buildTags = Build.TAGS
        return buildTags != null && buildTags.contains("test-keys")
    }
    
    /**
     * Check if app signature is valid (anti-repackaging)
     */
    fun isAppTampered(): Boolean {
        return try {
            val packageInfo = context.packageManager.getPackageInfo(
                context.packageName,
                PackageManager.GET_SIGNATURES
            )
            
            // In production: compare with known good signature
            val currentSignature = packageInfo.signatures[0].toCharsString()
            val expectedSignature = "YOUR_EXPECTED_SIGNATURE_HERE"
            
            currentSignature != expectedSignature
            
        } catch (e: Exception) {
            true  // If we can't verify, assume tampered
        }
    }
    
    /**
     * Check if running in emulator
     */
    fun isEmulator(): Boolean {
        return (Build.FINGERPRINT.startsWith("generic") ||
                Build.FINGERPRINT.startsWith("unknown") ||
                Build.MODEL.contains("google_sdk") ||
                Build.MODEL.contains("Emulator") ||
                Build.MODEL.contains("Android SDK") ||
                Build.MANUFACTURER.contains("Genymotion") ||
                Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic"))
    }
    
    /**
     * Check if debugging is enabled
     */
    fun isDebuggerAttached(): Boolean {
        return android.os.Debug.isDebuggerConnected()
    }
    
    /**
     * Comprehensive security check
     */
    fun performSecurityCheck(): SecurityCheckResult {
        val isRooted = isDeviceRooted()
        val isTampered = isAppTampered()
        val isEmulator = isEmulator()
        val isDebugging = isDebuggerAttached()
        
        val threatLevel = when {
            isRooted && isTampered -> "critical"
            isRooted || isTampered -> "high"
            isEmulator || isDebugging -> "medium"
            else -> "safe"
        }
        
        return SecurityCheckResult(
            isRooted = isRooted,
            isTampered = isTampered,
            isEmulator = isEmulator,
            isDebugging = isDebugging,
            threatLevel = threatLevel
        )
    }
}

data class SecurityCheckResult(
    val isRooted: Boolean,
    val isTampered: Boolean,
    val isEmulator: Boolean,
    val isDebugging: Boolean,
    val threatLevel: String
)
