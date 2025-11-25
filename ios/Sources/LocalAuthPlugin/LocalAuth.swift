import Foundation
import LocalAuthentication

/**
 * Swift implementation of the LocalAuth plugin for iOS.
 * 
 * This class wraps the iOS LocalAuthentication framework to provide
 * biometric and device credential authentication capabilities.
 */
@objc public class LocalAuth: NSObject {
    /**
     * Checks what authentication methods are available on the device.
     * 
     * This method uses LAContext to determine if the device supports:
     * - Biometric authentication (Touch ID or Face ID)
     * - Device credentials (passcode)
     * 
     * @return Dictionary containing the availability status of authentication methods
     */
    @objc public func checkAvailability() -> [String: Bool] {
        let context = LAContext()
        var error: NSError?

        // Check if biometric authentication is available
        // This includes Touch ID and Face ID depending on the device
        let canEvaluateBiometrics = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)

        // Only consider biometrics available if enrolled (not just hardware capability)
        // This prevents incorrectly reporting availability when biometrics exist but aren't enrolled
        let biometricsAvailable = canEvaluateBiometrics && (error as? LAError)?.code != .biometryNotEnrolled

        // Check if device credentials (passcode) is available
        // .deviceOwnerAuthentication includes both biometrics and passcode
        let canEvaluateDeviceCredentials = context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)

        return [
            "biometrics": biometricsAvailable,
            "deviceCredentials": canEvaluateDeviceCredentials,
            "available": biometricsAvailable || canEvaluateDeviceCredentials
        ]
    }
    
    /**
     * Attempts to authenticate the user using available methods.
     * 
     * This method will first try to use biometric authentication if available.
     * If biometrics are not available, it will fall back to device passcode.
     * 
     * @param reason The reason for authentication, displayed to the user
     * @param completion Callback that receives the authentication result
     */
    @objc public func authenticate(reason: String, completion: @escaping (Bool, String?) -> Void) {
        let context = LAContext()
        var error: NSError?
        
        // Check if biometric authentication is available
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            // Use biometric authentication (Touch ID or Face ID)
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, error in
                if let error = error {
                    // Authentication failed with an error
                    completion(false, error.localizedDescription)
                } else {
                    // Authentication succeeded or was canceled
                    completion(success, nil)
                }
            }
        } else if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) {
            // Fallback to device passcode if biometrics are not available
            context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, error in
                if let error = error {
                    // Authentication failed with an error
                    completion(false, error.localizedDescription)
                } else {
                    // Authentication succeeded or was canceled
                    completion(success, nil)
                }
            }
        } else {
            // No authentication method available
            if let error = error {
                completion(false, error.localizedDescription)
            } else {
                completion(false, "Authentication not available")
            }
        }
    }
}
