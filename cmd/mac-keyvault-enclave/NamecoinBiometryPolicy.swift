import Foundation
import LocalAuthentication
import Security

// Capability observations are not authentication or consent. Only the fresh
// production LAContext supplies one; the same context must still evaluate the
// biometrics-only policy successfully before the private operation may run.
enum NativeNamecoinBiometryObservation {
    case available(LABiometryType)
    case unavailable(LAError.Code?)
}

enum NativeNamecoinBiometryPolicy {
    // A positive allowlist also rejects future biometric modalities. Capability
    // denial, unavailable enrollment, lockout and absent modality are closed;
    // no underlying OS description or alternate policy is exposed or retried.
    static func refusal(for observation: NativeNamecoinBiometryObservation) -> HelperError? {
        if case .available(let modality) = observation, modality == .touchID {
            return nil
        }
        return HelperError(code: "presence_unavailable", status: errSecNotAvailable,
                           message: "Namecoin Touch ID unavailable")
    }

    static func requireTouchID(on context: LAContext) throws {
        // canEvaluatePolicy must precede reading biometryType on this actual
        // context. A denial never becomes an available observation, even if a
        // device reported Touch ID in an earlier context or capability check.
        let observation: NativeNamecoinBiometryObservation
        var capabilityError: NSError?
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &capabilityError) {
            observation = .available(context.biometryType)
        } else {
            let code = capabilityError.flatMap { error in
                error.domain == LAError.errorDomain ? LAError.Code(rawValue: error.code) : nil
            }
            observation = .unavailable(code)
        }
        if let refusal = refusal(for: observation) { throw refusal }
    }
}
