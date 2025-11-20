package io.revlabs.capacitor.localauth;

import android.app.Activity;
import android.content.Context;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.FragmentActivity;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executor;

/**
 * Implementation of local authentication for Android.
 * 
 * This class uses androidx.biometric library to provide authentication
 * using biometrics (fingerprint, face, iris) or device credentials
 * (PIN, pattern, password).
 */
public class LocalAuth {
    private static final String TAG = "LocalAuth";

    /**
     * Checks what authentication methods are available on the device.
     * 
     * This method uses BiometricManager to determine if the device supports:
     * - Biometric authentication (fingerprint, face recognition, etc.)
     * - Device credentials (PIN, pattern, password)
     * 
     * @param context The Android context used to access system services
     * @return Map containing the availability status of authentication methods
     */
    public Map<String, Boolean> checkAvailability(Context context) {
        BiometricManager biometricManager = BiometricManager.from(context);
        
        // Check for biometric authentication availability (fingerprint, face recognition, etc.)
        int canAuthenticateBiometrics = biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG);
        
        // Check for device credential authentication availability (PIN, pattern, password)
        int canAuthenticateDeviceCredential = biometricManager.canAuthenticate(BiometricManager.Authenticators.DEVICE_CREDENTIAL);
        
        // Biometrics are available if the result is SUCCESS
        boolean biometricsAvailable = canAuthenticateBiometrics == BiometricManager.BIOMETRIC_SUCCESS;
        
        // Device credentials are available if the result is SUCCESS
        boolean deviceCredentialsAvailable = canAuthenticateDeviceCredential == BiometricManager.BIOMETRIC_SUCCESS;
        
        // Create and return the result map
        Map<String, Boolean> result = new HashMap<>();
        result.put("biometrics", biometricsAvailable);
        result.put("deviceCredentials", deviceCredentialsAvailable);
        result.put("available", biometricsAvailable || deviceCredentialsAvailable);
        
        return result;
    }

    /**
     * Callback interface for authentication results.
     * This allows the plugin to receive asynchronous results from the authentication process.
     */
    public interface AuthCallback {
        /**
         * Called when authentication completes.
         * 
         * @param success Whether authentication was successful
         * @param error Error message if authentication failed, null otherwise
         */
        void onResult(boolean success, String error);
    }

    /**
     * Attempts to authenticate the user using available methods.
     * 
     * This method shows a BiometricPrompt that allows the user to authenticate
     * using biometrics (fingerprint, face, iris) or device credentials (PIN, pattern, password).
     * 
     * @param activity The activity used to show the authentication dialog
     * @param title The title for the authentication dialog
     * @param subtitle The subtitle/reason for the authentication dialog
     * @param cancelButtonText The text for the negative/cancel button (only used when not using device credentials)
     * @param confirmationRequired Whether to require explicit user confirmation after authentication
     * @param callback The callback to receive the authentication result
     */
    public void authenticate(FragmentActivity activity, String title, String subtitle, boolean confirmationRequired, final AuthCallback callback) {
        // Create an executor to run authentication operations on the main thread
        Executor executor = ContextCompat.getMainExecutor(activity);
        
        // Create a BiometricPrompt with appropriate callbacks
        BiometricPrompt biometricPrompt = new BiometricPrompt(activity, executor, new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
                // Authentication error (e.g., canceled by user, timeout, etc.)
                Log.e(TAG, "Authentication error: " + errString);
                callback.onResult(false, errString.toString());
            }

            @Override
            public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                super.onAuthenticationSucceeded(result);
                // Authentication succeeded
                Log.i(TAG, "Authentication succeeded");
                callback.onResult(true, null);
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
                // Authentication failed (e.g., fingerprint not recognized)
                // Note: We don't call the callback here because the biometric prompt stays open
                // to allow multiple attempts
                Log.e(TAG, "Authentication failed");
            }
        });

        // Configure the BiometricPrompt settings
        BiometricPrompt.PromptInfo.Builder promptInfoBuilder = new BiometricPrompt.PromptInfo.Builder()
                .setTitle(title != null ? title : "Authentication")
                .setSubtitle(subtitle != null ? subtitle : "Please authenticate to continue");

        // Android API level determines how to configure authentication methods
        // API 30+ supports BIOMETRIC_STRONG | DEVICE_CREDENTIAL combination
        // API 28-29 requires using the deprecated setDeviceCredentialAllowed() method
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // API 30 (Android 11) and above: Use the modern approach
            promptInfoBuilder.setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_STRONG | BiometricManager.Authenticators.DEVICE_CREDENTIAL
            );
        } else {
            // API 28-29: Use the deprecated method for backward compatibility
            promptInfoBuilder
                .setDeviceCredentialAllowed(true);
        }

        // Build the final prompt configuration
        BiometricPrompt.PromptInfo promptInfo = promptInfoBuilder.build();
        
        // Show the biometric prompt on the main thread to avoid threading issues
        new Handler(Looper.getMainLooper()).post(() -> {
            biometricPrompt.authenticate(promptInfo);
        });
    }
}
