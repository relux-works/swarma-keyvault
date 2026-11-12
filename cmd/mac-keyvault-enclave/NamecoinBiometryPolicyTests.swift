// Swift Testing SOURCE only. These public capability observations exercise the
// exact production allowlist/refusal constructor. They do not construct or
// authenticate LAContext, invoke UI/private work, or prove native capability,
// full review, freshness, Touch ID or owner consent. All execution is NOT_RUN.
import Foundation
import LocalAuthentication
import Security
import Testing
@testable import KeyvaultNativeCore

private func expectNamecoinCapabilityUnavailable(_ observation: NativeNamecoinBiometryObservation) {
    guard let refusal = NativeNamecoinBiometryPolicy.refusal(for: observation) else {
        Issue.record("Expected the fixed capability refusal")
        return
    }
    #expect(refusal.code == "presence_unavailable")
    #expect(refusal.status == KeyvaultNativeCore.errSecNotAvailable)
    #expect(refusal.message == "Namecoin Touch ID unavailable")
}

struct NamecoinBiometryPolicyTests {
    // Positive control: the capability predicate admits Touch ID only. A nil
    // refusal does not assert successful authentication or authorize private use.
    @Test func touchIDCapabilityIsAdmitted() {
        #expect(NativeNamecoinBiometryPolicy.refusal(for: .available(.touchID)) == nil)
    }

    // A failed canEvaluatePolicy result is represented only as unavailable,
    // independently of the measured OS error code. No category permits a retry.
    // These distinct SDK failure examples all have that same closed observation;
    // they are not simulated LAContext responses or native denial evidence.
    @Test(arguments: [LAError.Code.biometryNotAvailable, .biometryNotEnrolled,
                      .biometryLockout, .passcodeNotSet, .authenticationFailed,
                      .userCancel, .systemCancel, .appCancel, .invalidContext,
                      .notInteractive, .userFallback])
    func capabilityDenialsAreClosed(_ denied: LAError.Code) {
        expectNamecoinCapabilityUnavailable(.unavailable(denied))
    }

    // An absent or unrecognized capability error also remains unavailable.
    @Test func unspecifiedCapabilityDenialIsClosed() {
        expectNamecoinCapabilityUnavailable(.unavailable(nil))
    }

    // Genuine alternative SDK modalities must not pass the Touch ID allowlist.
    @Test func absentAndFaceIDModalitiesAreClosed() {
        expectNamecoinCapabilityUnavailable(.available(.none))
        expectNamecoinCapabilityUnavailable(.available(.faceID))
    }

    @available(macOS 14.0, *)
    @Test func opticIDModalityIsClosed() {
        expectNamecoinCapabilityUnavailable(.available(.opticID))
    }

    // Unrecognized values are rejected by the equality allowlist. This public
    // enum fixture does not imply the OS can actually report that modality.
    @Test func futureModalityIsClosed() throws {
        let modality = try #require(LABiometryType(rawValue: Int.max))
        expectNamecoinCapabilityUnavailable(.available(modality))
    }
}
