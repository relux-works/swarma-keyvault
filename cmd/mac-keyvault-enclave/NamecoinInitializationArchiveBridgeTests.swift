// SOURCE / NOT_RUN. Public selection, bounded copy and software lifecycle
// controls only. No test calls valid production Open, Complete, withAccount,
// native storage, Keychain, TouchID or owner UI. Valid Open reserves the actual
// home gate, so its positive native lane is attended/separately admitted only.
import CryptoKit
import Darwin
import Foundation
import NamecoinArchiveABI
import Testing
@testable import KeyvaultNativeCore

private let initializationProfiles: [(name: String, bytes: Data, sha256: String)] = [
    ("two-stage-reservation", Data(#"{"schema":"keyvault-namecoin-native-selection/1","selection":{"Network":"namecoin-regtest","Genesis":"0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206","Group":"fixture/recovery@1","Account":"fixture/namecoin@1","AccountPinSHA256":"f6ac65655048daea9dedbb6088eb1c3d15582877023491b1c1f7b4dcb56aa833","Policy":{"revision":"neutral-core28-fixture-v2","per_tx_fee_cap_atoms":"100000","total_fee_cap_atoms":"400000","min_fee_rate_atoms_per_kvb":"100000","max_fee_rate_atoms_per_kvb":"1000000","dust_relay_fee_atoms_per_kvb":"3000","created_at":1794477600,"release_not_after":1794564000,"final_confirmations":1,"release_mode":"two-stage"},"RevealValuesPin":null},"sidecar":{"Binding":{"Group":"fixture/recovery@1","Account":"fixture/namecoin@1","PublicPin":[246,172,101,101,80,72,218,234,157,237,187,96,136,235,28,61,21,88,40,119,2,52,145,177,193,247,180,220,181,106,168,51],"Policy":"neutral-core28-fixture-v2"},"NostrAccount":"fixture/nostr@1","GroupID":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"NostrPublicPin":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"MetadataHash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"PairedValueHash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}}"#.utf8), "3d65f535a3a21c46651b90088567afe908bd0e4368cb74aa7ae8f5af1352f07d"),
    ("two-stage-reveal", Data(#"{"schema":"keyvault-namecoin-native-selection/1","selection":{"Network":"namecoin-regtest","Genesis":"0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206","Group":"fixture/recovery@1","Account":"fixture/namecoin@1","AccountPinSHA256":"f6ac65655048daea9dedbb6088eb1c3d15582877023491b1c1f7b4dcb56aa833","Policy":{"revision":"neutral-core28-fixture-v2","per_tx_fee_cap_atoms":"100000","total_fee_cap_atoms":"400000","min_fee_rate_atoms_per_kvb":"100000","max_fee_rate_atoms_per_kvb":"1000000","dust_relay_fee_atoms_per_kvb":"3000","created_at":1794477600,"release_not_after":1794564000,"final_confirmations":1,"release_mode":"two-stage"},"RevealValuesPin":"eyJzY2hlbWEiOiJrZXl2YXVsdC1uYW1lY29pbi1yZXZlYWwtdmFsdWVzLzEiLCJyZXNlcnZhdGlvbl9wbGFuX3NoYTI1NiI6ImQ5MDkzNWY5MmMwNTYzODQ0ZmI2YmQ0OWIzZjVmMjExZjcwYTg3MzYxMTRiMWI1OWVkNGRjZGQ5N2FiZWQ5NjciLCJyZWdpc3RyYXRpb25zIjpbeyJuYW1lX2hleCI6IjY5NjQyZjY2Njk3ODc0NzU3MjY1MmQ3Mzc0NjE2NzY1NjQiLCJ2YWx1ZV9oZXgiOiI3YjIyNmU2ZjczNzQ3MjIyM2E3YjIyNmU2MTZkNjU3MzIyM2E3YjIyNWYyMjNhMjIzNzM5NjI2NTM2MzYzNzY1NjYzOTY0NjM2MjYyNjE2MzM1MzU2MTMwMzYzMjM5MzU2MzY1MzgzNzMwNjIzMDM3MzAzMjM5NjI2NjYzNjQ2MjMyNjQ2MzY1MzIzODY0MzkzNTM5NjYzMjM4MzEzNTYyMzEzNjY2MzgzMTM3MzkzODIyN2Q3ZDJjMjI3Mzc3NjE3MjZkNjEyMjNhN2IyMjZjNjE2ZTY0NmM2ZjcyNjQyMjNhN2IyMjY3NzI2MTZlNzQyMjNhMjI2NjM5MzMzMDM4NjEzMDMxMzkzMjM1Mzg2MzMzMzEzMDM0MzkzMzM0MzQ2NjM4MzU2NjM4Mzk2NDM1MzIzMjM5NjIzNTMzMzE2MzM4MzQzNTM4MzMzNjY2MzkzOTYyMzAzODM2MzAzMTY2MzEzMTMzNjI2MzY1MzAzMzM2NjYzOTIyN2Q3ZDdkIiwidmFsdWVfc2hhMjU2IjoiMmM1NTY3YmE0NWU4YjIzYjRhZWJiODY1MDUwMTZhZTA3MjViNWMzY2VjNWJlZjU4Yjc5NTQ5ZjIyZWRiMTVjMiJ9LHsibmFtZV9oZXgiOiI2NDJmNjY2OTc4NzQ3NTcyNjUyZDczNzQ2MTY3NjU2NCIsInZhbHVlX2hleCI6IjdiMjI2ZTZmNzM3NDcyMjIzYTdiMjI2ZTYxNmQ2NTczMjIzYTdiMjI1ZjIyM2EyMjM3Mzk2MjY1MzYzNjM3NjU2NjM5NjQ2MzYyNjI2MTYzMzUzNTYxMzAzNjMyMzkzNTYzNjUzODM3MzA2MjMwMzczMDMyMzk2MjY2NjM2NDYyMzI2NDYzNjUzMjM4NjQzOTM1Mzk2NjMyMzgzMTM1NjIzMTM2NjYzODMxMzczOTM4MjI3ZDdkN2QiLCJ2YWx1ZV9zaGEyNTYiOiI5NjcyM2U4ZmRiNTMxMzFhMTg2NTAyNjJjYjJhYTg2M2RhZjA2NDgwOTQ5ZDhiYmUxM2JhODcxNTNlNmI4ZGE1In1dfQ=="},"sidecar":{"Binding":{"Group":"fixture/recovery@1","Account":"fixture/namecoin@1","PublicPin":[246,172,101,101,80,72,218,234,157,237,187,96,136,235,28,61,21,88,40,119,2,52,145,177,193,247,180,220,181,106,168,51],"Policy":"neutral-core28-fixture-v2"},"NostrAccount":"fixture/nostr@1","GroupID":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"NostrPublicPin":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"MetadataHash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"PairedValueHash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}}"#.utf8), "81d95f012c14e823e228cc432eb3816f204708747f512282753b3347d7e11237"),
    ("all-four-before-release-reservation", Data(#"{"schema":"keyvault-namecoin-native-selection/1","selection":{"Network":"namecoin-regtest","Genesis":"0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206","Group":"fixture/recovery@1","Account":"fixture/namecoin@1","AccountPinSHA256":"f6ac65655048daea9dedbb6088eb1c3d15582877023491b1c1f7b4dcb56aa833","Policy":{"revision":"neutral-core28-fixture-v2","per_tx_fee_cap_atoms":"100000","total_fee_cap_atoms":"400000","min_fee_rate_atoms_per_kvb":"100000","max_fee_rate_atoms_per_kvb":"1000000","dust_relay_fee_atoms_per_kvb":"3000","created_at":1794477600,"release_not_after":1794564000,"final_confirmations":1,"release_mode":"all-four-before-release"},"RevealValuesPin":null},"sidecar":{"Binding":{"Group":"fixture/recovery@1","Account":"fixture/namecoin@1","PublicPin":[246,172,101,101,80,72,218,234,157,237,187,96,136,235,28,61,21,88,40,119,2,52,145,177,193,247,180,220,181,106,168,51],"Policy":"neutral-core28-fixture-v2"},"NostrAccount":"fixture/nostr@1","GroupID":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"NostrPublicPin":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"MetadataHash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"PairedValueHash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}}"#.utf8), "c55494c9147d3c2965a16dc6b0e85e350711a728c27007aaeea793c708cd7aa7"),
    ("all-four-before-release-reveal", Data(#"{"schema":"keyvault-namecoin-native-selection/1","selection":{"Network":"namecoin-regtest","Genesis":"0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206","Group":"fixture/recovery@1","Account":"fixture/namecoin@1","AccountPinSHA256":"f6ac65655048daea9dedbb6088eb1c3d15582877023491b1c1f7b4dcb56aa833","Policy":{"revision":"neutral-core28-fixture-v2","per_tx_fee_cap_atoms":"100000","total_fee_cap_atoms":"400000","min_fee_rate_atoms_per_kvb":"100000","max_fee_rate_atoms_per_kvb":"1000000","dust_relay_fee_atoms_per_kvb":"3000","created_at":1794477600,"release_not_after":1794564000,"final_confirmations":1,"release_mode":"all-four-before-release"},"RevealValuesPin":"eyJzY2hlbWEiOiJrZXl2YXVsdC1uYW1lY29pbi1yZXZlYWwtdmFsdWVzLzEiLCJyZXNlcnZhdGlvbl9wbGFuX3NoYTI1NiI6IjJkODE3ZGVhNjgxY2RhMWVlODIwNmFiOGY1YTQ0NmRjY2YxN2NiMmEzMDllMGVkMTE0OTIyNDdmNWJhZGRiNTMiLCJyZWdpc3RyYXRpb25zIjpbeyJuYW1lX2hleCI6IjY5NjQyZjY2Njk3ODc0NzU3MjY1MmQ2YzYxNmU2NDZjNmY3MjY0IiwidmFsdWVfaGV4IjoiN2IyMjZlNmY3Mzc0NzIyMjNhN2IyMjZlNjE2ZDY1NzMyMjNhN2IyMjVmMjIzYTIyMzczOTYyNjUzNjM2Mzc2NTY2Mzk2NDYzNjI2MjYxNjMzNTM1NjEzMDM2MzIzOTM1NjM2NTM4MzczMDYyMzAzNzMwMzIzOTYyNjY2MzY0NjIzMjY0NjM2NTMyMzg2NDM5MzUzOTY2MzIzODMxMzU2MjMxMzY2NjM4MzEzNzM5MzgyMjdkN2QyYzIyNzM3NzYxNzI2ZDYxMjIzYTdiMjI2YzYxNmU2NDZjNmY3MjY0MjIzYTdiMjI2NzcyNjE2ZTc0MjIzYTIyNjYzOTMzMzAzODYxMzAzMTM5MzIzNTM4NjMzMzMxMzAzNDM5MzMzNDM0NjYzODM1NjYzODM5NjQzNTMyMzIzOTYyMzUzMzMxNjMzODM0MzUzODMzMzY2NjM5Mzk2MjMwMzgzNjMwMzE2NjMxMzEzMzYyNjM2NTMwMzMzNjY2MzkyMjdkN2Q3ZCIsInZhbHVlX3NoYTI1NiI6IjJjNTU2N2JhNDVlOGIyM2I0YWViYjg2NTA1MDE2YWUwNzI1YjVjM2NlYzViZWY1OGI3OTU0OWYyMmVkYjE1YzIifSx7Im5hbWVfaGV4IjoiNjQyZjY2Njk3ODc0NzU3MjY1MmQ2YzYxNmU2NDZjNmY3MjY0IiwidmFsdWVfaGV4IjoiN2IyMjZlNmY3Mzc0NzIyMjNhN2IyMjZlNjE2ZDY1NzMyMjNhN2IyMjVmMjIzYTIyMzczOTYyNjUzNjM2Mzc2NTY2Mzk2NDYzNjI2MjYxNjMzNTM1NjEzMDM2MzIzOTM1NjM2NTM4MzczMDYyMzAzNzMwMzIzOTYyNjY2MzY0NjIzMjY0NjM2NTMyMzg2NDM5MzUzOTY2MzIzODMxMzU2MjMxMzY2NjM4MzEzNzM5MzgyMjdkN2Q3ZCIsInZhbHVlX3NoYTI1NiI6Ijk2NzIzZThmZGI1MzEzMWExODY1MDI2MmNiMmFhODYzZGFmMDY0ODA5NDlkOGJiZTEzYmE4NzE1M2U2YjhkYTUifV19"},"sidecar":{"Binding":{"Group":"fixture/recovery@1","Account":"fixture/namecoin@1","PublicPin":[246,172,101,101,80,72,218,234,157,237,187,96,136,235,28,61,21,88,40,119,2,52,145,177,193,247,180,220,181,106,168,51],"Policy":"neutral-core28-fixture-v2"},"NostrAccount":"fixture/nostr@1","GroupID":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"NostrPublicPin":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"MetadataHash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"PairedValueHash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}}"#.utf8), "ad8afb2a9c7ed519bfe96405c8b4de967fd041314e39dd0afae451160fd456dd"),
]
private let initializationPin = Data(#"{"schema":"keyvault-namecoin-account-pin/1","group":"fixture/recovery@1","account":"fixture/namecoin@1","account_xpub":"xpub6CrykXqxNRHLxTepHk2aQGtfXDTHdPmk7oRffJQg89vem5s1BQR9uLJAtXT8LHjxCDMJ2Myp29dU2vfvLVKaXgYC1PG9tHnyZbB8KoENAWx","master_fingerprint":"3442193e","account_path":"m/84h/7h/0h"}"#.utf8)

private func initRefusal(_ code: String, _ operation: () throws -> Void) {
    do { try operation(); Issue.record("Expected fixed initialization refusal") }
    catch let failure as NativeNamecoinArchiveFailure { #expect(failure.code == code) }
    catch { Issue.record("Unexpected error type; raw diagnostics omitted") }
}
private func initReplacing(_ object: NativeArchiveJSON, _ key: String, _ value: NativeArchiveJSON?) throws -> NativeArchiveJSON {
    guard case .object(let fields) = object else { throw NativeNamecoinArchiveFailure("policy_refused") }
    return .object(fields.compactMap { field in field.0 == key ? value.map { (key, $0) } : field })
}
private func initOctets(_ value: Data) -> NativeArchiveJSON { .array(value.map { .number(UInt64($0)) }) }

// PUBLIC fixture assembly, not an alternate engine, native admission oracle,
// old-item provenance or hardware provider. Hash placeholders stay public.
private struct InitializationFixture {
    let config: Data
    let pin: Data
    let journal: NativeJournalSelection
    let plan: NativeJournalOperationPlan
    init(config: Data = initializationProfiles[0].bytes, pin: Data = initializationPin,
         helper: Data = Data(repeating: 0x44, count: 20), adoption: Data = Data(repeating: 0x55, count: 32)) throws {
        self.config = config; self.pin = pin
        let top = try NativeArchiveJSON.decode(config, maximum: 4 << 20, canonical: true)
        let values = try top.field("selection")
        let sidecar = try top.field("sidecar")
        let group = try values.field("Group").text(), account = try values.field("Account").text()
        let publicPin = try nativeArchiveUnhex(values.field("AccountPinSHA256").text(), count: 32)
        let revision = try values.field("Policy").field("revision").text()
        var encoded = Data("KVNS1\0".utf8)
        for identity in [group, account] { encoded.append(nativeJournalLP(Data(identity.utf8))) }
        encoded.append(publicPin); encoded.append(nativeJournalLP(Data(revision.utf8)))
        encoded.append(nativeJournalLP(Data(try sidecar.field("NostrAccount").text().utf8)))
        for (name, count) in [("GroupID", 16), ("NostrPublicPin", 32), ("MetadataHash", 32), ("PairedValueHash", 32)] {
            encoded.append(try sidecar.field(name).octets(count))
        }
        journal = try NativeJournalSelection(group: group, account: account, publicPin: publicPin,
            policy: revision, helperCDHash: helper, sidecar: encoded)
        plan = try NativeJournalOperationPlan(kind: .initialize, selection: journal, adoptionPlanDigest: adoption)
    }
    func selection(profile: Data? = nil, pin: Data? = nil, expected: String? = nil,
                   plan: NativeJournalOperationPlan? = nil) throws -> NativeNamecoinInitializationSelection {
        let bytes = profile ?? config
        return try NativeNamecoinInitializationSelection(selectedAccountPin: pin ?? self.pin,
            trustedCanonicalSelection: bytes, trustedProfileSHA256: expected ?? nativeArchiveHex(Data(SHA256.hash(data: bytes))),
            plan: plan ?? self.plan)
    }
    func withReboundPin(_ pin: Data) throws -> InitializationFixture {
        let object = try NativeArchiveJSON.decode(config, maximum: 4 << 20, canonical: true)
        let hash = Data(SHA256.hash(data: pin))
        let selection = try initReplacing(object.field("selection"), "AccountPinSHA256", .string(nativeArchiveHex(hash)))
        let oldSidecar = try object.field("sidecar")
        let binding = try initReplacing(oldSidecar.field("Binding"), "PublicPin", initOctets(hash))
        let sidecar = try initReplacing(oldSidecar, "Binding", binding)
        let changed = try initReplacing(initReplacing(object, "selection", selection), "sidecar", sidecar).canonical()
        return try InitializationFixture(config: changed, pin: pin)
    }
}

// Fixture borrowing only, with no independent validator/oracle. Tests exercise
// the exact raw query/copy function used by both real native load callbacks.
private func copyInitializationFixture(_ value: NativeSecretBytes, buffer: UnsafeMutablePointer<UInt8>?,
                                       capacity: size_t, written: UnsafeMutablePointer<size_t>?) throws {
    try value.withBytes { try NativeInitializationABI.copyProtected($0, buffer: buffer, capacity: capacity, written: written) }
}

struct NamecoinInitializationArchiveBridgeTests {
    // All four actual literal Go profiles; nullable RevealValuesPin is a valid
    // reservation form. Public decoding/review binding only, not valid C Open.
    @Test func fourKnownPublicProfilesAndFullReview() throws {
        for profile in initializationProfiles {
            let fixture = try InitializationFixture(config: profile.bytes)
            let selected = try fixture.selection(expected: profile.sha256)
            #expect(selected.selected.raw == profile.bytes)
            #expect(selected.selected.group == "fixture/recovery@1")
            #expect(selected.selected.account == "fixture/namecoin@1")
            #expect(selected.profileSHA256 == Data(SHA256.hash(data: profile.bytes)))
            try selected.verifyBinding(to: fixture.journal)
            let snapshot = try selected.snapshot()
            #expect(snapshot.operation == .journalInitialize)
            #expect(snapshot.feeAtoms == 0)
            #expect(snapshot.digest == Data(SHA256.hash(data: selected.reviewFrame)))
            for text in ["INITIALIZE JOURNAL ONLY", "fixture/recovery@1", "fixture/nostr@1", "fixture/namecoin@1",
                         "Separate adoption sitting", NativeJournalSelection.service, fixture.journal.locator,
                         String(decoding: profile.bytes, as: UTF8.self), String(decoding: initializationPin, as: UTF8.self)] {
                #expect(snapshot.text.contains(text))
            }
            #expect(snapshot.text.hasSuffix("END OF COMPLETE INTERNAL REVIEW"))
            #expect(snapshot.reason.contains(nativeArchiveHex(snapshot.digest)))
            let config = try NativeArchiveJSON.decode(profile.bytes, maximum: 4 << 20, canonical: true)
            if profile.name.hasSuffix("reservation") {
                guard case .null = try config.field("selection").field("RevealValuesPin") else { Issue.record("Expected legitimate null reveal pin"); return }
            } else { #expect(!(try config.field("selection").field("RevealValuesPin").base64(maximum: 2 << 20)).isEmpty) }
        }
    }

    // Foreign mutable public input cannot change frozen config, pin, metadata,
    // review digest or adoption frame. No account/private buffer is inspected.
    @Test func publicOwnershipAndAdoptionBinding() throws {
        let fixture = try InitializationFixture()
        let mutableConfig = NSMutableData(data: fixture.config), mutablePin = NSMutableData(data: fixture.pin)
        let selected = try fixture.selection(profile: Data(referencing: mutableConfig), pin: Data(referencing: mutablePin))
        let before = try selected.snapshot()
        mutableConfig.replaceBytes(in: NSRange(location: 0, length: 1), withBytes: [UInt8(0)], length: 1)
        mutablePin.replaceBytes(in: NSRange(location: 0, length: 1), withBytes: [UInt8(0)], length: 1)
        #expect(selected.selected.raw == fixture.config)
        #expect(selected.pin == fixture.pin)
        #expect(try selected.snapshot().digest == before.digest)
        let other = try InitializationFixture(adoption: Data(repeating: 0x56, count: 32))
        #expect(try other.selection().snapshot().digest != before.digest)
        let differentCode = try InitializationFixture(helper: Data(repeating: 0x45, count: 20))
        initRefusal("adoption_required") { try selected.verifyBinding(to: differentCode.journal) }
        let reconcile = try NativeJournalOperationPlan(kind: .reconcile, selection: fixture.journal, adoptionPlanDigest: fixture.plan.adoptionPlanDigest)
        initRefusal("policy_refused") { _ = try fixture.selection(plan: reconcile) }
    }

    // Representation and independent profile hash failures have fixed18; full
    // valid controls are above. Hash is recomputed ONLY to isolate parser cases.
    @Test func closedProfileAndHashRefusals() throws {
        let fixture = try InitializationFixture()
        let text = String(decoding: fixture.config, as: UTF8.self)
        for bytes in [Data(), Data("null".utf8), fixture.config + Data([32]), fixture.config + Data("{}".utf8),
                      Data(text.replacingOccurrences(of: "\"schema\":", with: "\"schema\":\"wrong\",\"schema\":").utf8),
                      Data(text.replacingOccurrences(of: "\"schema\":", with: "\"Schema\":").utf8),
                      Data(text.replacingOccurrences(of: "\"sidecar\":{", with: "\"sidecar\":null,\"unused\":{").utf8),
                      Data(repeating: 65, count: (4 << 20) + 1)] {
            initRefusal("policy_refused") { _ = try fixture.selection(profile: bytes) }
        }
        for hash in ["", String(repeating: "0", count: 64), String(repeating: "g", count: 64),
                     nativeArchiveHex(Data(SHA256.hash(data: fixture.config))).uppercased()] {
            initRefusal("policy_refused") { _ = try fixture.selection(expected: hash) }
        }
        let parsed = try NativeArchiveJSON.decode(fixture.config, maximum: 4 << 20, canonical: true)
        for (key, value) in [("Group", "other/recovery@1"), ("Account", "fixture/namecoin@2")] {
            let changed = try initReplacing(parsed.field("selection"), key, .string(value))
            let bytes = try initReplacing(parsed, "selection", changed).canonical()
            initRefusal("account_mismatch") { _ = try fixture.selection(profile: bytes) }
        }
        for value in [try initReplacing(parsed, "selection", nil), try initReplacing(parsed, "selection", .null)] {
            initRefusal("policy_refused") { _ = try fixture.selection(profile: value.canonical()) }
        }
    }

    // Closed six-field pin, exact path/identity and hash correspondence. Native
    // shape is not a second secp256k1/Base58Check implementation or oracle.
    @Test func accountPinRefusalsAndNoAliasForms() throws {
        let fixture = try InitializationFixture()
        initRefusal("account_mismatch") { _ = try fixture.selection(pin: fixture.pin + Data([32])) }
        let parsed = try NativeArchiveJSON.decode(fixture.pin, maximum: 16384, canonical: true)
        for (key, value) in [("group", "other/recovery@1"), ("account", "fixture/namecoin@2"),
                             ("account_path", "m/84h/7h/1h"), ("account_xpub", "bad\npoint"),
                             ("master_fingerprint", "3442193E"), ("schema", "wrong")] {
            let raw = try initReplacing(parsed, key, .string(value)).canonical()
            let altered = try fixture.withReboundPin(raw)
            initRefusal("account_mismatch") { _ = try altered.selection() }
        }
        for raw in [Data("null".utf8), Data(), fixture.pin + Data([32]),
                    Data(String(decoding: fixture.pin, as: UTF8.self).replacingOccurrences(of: "\"account\":", with: "\"Account\":").utf8),
                    Data(String(decoding: fixture.pin, as: UTF8.self).replacingOccurrences(of: "\"schema\":", with: "\"schema\":\"wrong\",\"schema\":").utf8),
                    try initReplacing(parsed, "account_path", nil).canonical(),
                    Data(repeating: 65, count: 16385)] {
            let altered = try fixture.withReboundPin(raw)
            initRefusal("account_mismatch") { _ = try altered.selection() }
        }
    }

    // Full sidecar bytes/metadata are bound, not merely account strings.
    @Test func exactSidecarAndMetadataMismatch() throws {
        let fixture = try InitializationFixture(), selection = try fixture.selection()
        let object = try NativeArchiveJSON.decode(fixture.config, maximum: 4 << 20, canonical: true)
        let sidecar = try initReplacing(object.field("sidecar"), "MetadataHash", initOctets(Data(repeating: 1, count: 32)))
        let changed = try initReplacing(object, "sidecar", sidecar).canonical()
        initRefusal("account_mismatch") { _ = try fixture.selection(profile: changed) }
        let other = try InitializationFixture(config: changed)
        initRefusal("adoption_required") { try selection.verifyBinding(to: other.journal) }
        #expect(try other.selection().snapshot().digest != selection.snapshot().digest)
    }

    // Actual imported type and complete fixed table, no invocation of Complete
    // and no fabricated storage/hardware provider. Synthetic table stays local.
    @Test func callbackShapeAndLiteralStatusMapping() throws {
        var table = kv_nmc_init_callbacks_v1()
        initRefusal("invalid_request") { try NativeInitializationABI.requireCallbacks(table) }
        var publicMarker: UInt8 = 7
        try withUnsafeMutablePointer(to: &publicMarker) { marker in
            table.context = UnsafeMutableRawPointer(marker)
            table.require_absent = { _ in -1 }
            table.create_initialized_anchor = { _, _, _ in -1 }
            table.load_protected = { _, _, _, _ in -1 }
            try NativeInitializationABI.requireCallbacks(table)
            let complete = table
            table.require_absent = nil
            initRefusal("invalid_request") { try NativeInitializationABI.requireCallbacks(table) }
            table = complete; table.create_initialized_anchor = nil
            initRefusal("invalid_request") { try NativeInitializationABI.requireCallbacks(table) }
            table = complete; table.load_protected = nil
            initRefusal("invalid_request") { try NativeInitializationABI.requireCallbacks(table) }
            table = complete; table.context = nil
            initRefusal("invalid_request") { try NativeInitializationABI.requireCallbacks(table) }
        }
        for raw in Int32(1)...Int32(21) {
            #expect(NativeInitializationABI.completeResult(raw, possibleCreate: false, callbackFailed: true, completeReadback: false)?.code == NativeNamecoinArchiveFailure.codes[Int(raw) - 1])
            #expect(NativeInitializationABI.completeResult(raw, possibleCreate: true, callbackFailed: true, completeReadback: false)?.code == "outcome_unknown")
            #expect(NativeInitializationABI.closeResult(raw)?.code == "outcome_unknown")
        }
        #expect(NativeInitializationABI.completeResult(0, possibleCreate: true, callbackFailed: false, completeReadback: true) == nil)
        #expect(NativeInitializationABI.completeResult(0, possibleCreate: false, callbackFailed: false, completeReadback: false)?.code == "outcome_unknown")
        #expect(NativeInitializationABI.completeResult(0, possibleCreate: false, callbackFailed: false, completeReadback: true)?.code == "outcome_unknown")
        #expect(NativeInitializationABI.completeResult(0, possibleCreate: true, callbackFailed: true, completeReadback: true)?.code == "outcome_unknown")
        #expect(NativeInitializationABI.completeResult(0, possibleCreate: true, callbackFailed: false, completeReadback: false)?.code == "outcome_unknown")
        for raw in [Int32.min, -1, 22, 999, Int32.max] {
            #expect(NativeInitializationABI.completeResult(raw, possibleCreate: false, callbackFailed: false, completeReadback: false)?.code == "outcome_unknown")
        }
        #expect(NativeInitializationABI.closeResult(0) == nil)
    }

    // Only published marker bytes use NativeSecretBytes. Query/copy/refusals
    // verify no partial bytes/length leakage; not actual protected-anchor proof.
    @Test func boundedQueryCopyAndRefusalNoPartialWrite() throws {
        for count in [1, 512, 32768] {
            let marker = [UInt8](repeating: 0x5a, count: count)
            let owned = try marker.withUnsafeBytes { try NativeSecretBytes(copying: $0, maximum: 32768) }
            defer { owned.clear() }
            var written: size_t = 999
            try copyInitializationFixture(owned, buffer: nil, capacity: 0, written: &written)
            #expect(written == size_t(count))
            var destination = [UInt8](repeating: 0xaa, count: count + 1)
            try destination.withUnsafeMutableBufferPointer { buffer in
                try copyInitializationFixture(owned, buffer: buffer.baseAddress, capacity: size_t(min(count + 1, 32768)), written: &written)
            }
            #expect(written == size_t(count))
            #expect(Array(destination.prefix(count)) == marker)
            #expect(destination.last == 0xaa)
            destination = [UInt8](repeating: 0xaa, count: count + 1)
            try destination.withUnsafeMutableBufferPointer { buffer in
                for capacity in [size_t(0), size_t(count - 1), size_t(32769)] {
                    written = 999
                    initRefusal("journal_unavailable") {
                        try copyInitializationFixture(owned, buffer: buffer.baseAddress, capacity: capacity, written: &written)
                    }
                    #expect(written == 0)
                }
            }
            #expect(destination.allSatisfy { $0 == 0xaa })
            written = 999
            initRefusal("journal_unavailable") { try copyInitializationFixture(owned, buffer: nil, capacity: 1, written: &written) }
            #expect(written == 0)
            initRefusal("journal_unavailable") { try copyInitializationFixture(owned, buffer: nil, capacity: 0, written: nil) }
        }
    }

    // Single-use/refusal/gate-order software model only. The synthetic PUBLIC
    // marker is cleared before ownership is taken for Close. This is NOT a real
    // gate, a native account borrow, proof of zeroization or hardware evidence.
    @Test func syntheticCompletePanicClearBeforeSingleClose() throws {
        for raw in [Int32(0), 1, 5, 19, 20] {
            var state = NativeInitializationLifecycle()
            var ownership = try NativeArchiveHandleOwnership(7)
            var events: [String] = []
            do {
                let marker = [UInt8](repeating: 0x42, count: 64)
                let bytes = try marker.withUnsafeBytes { try NativeSecretBytes(copying: $0, maximum: 64) }
                defer { bytes.clear(); events.append("native-public-fixture-clear") }
                // Synthetic successful query only; no filesystem/native proof.
                try state.nativeRechecked(); try state.absenceReturned(0)
                try state.begin(); events.append("complete-return-" + String(raw))
                if raw == 0 { try state.returned(raw); try state.requireCompleted() }
                else { initRefusal(NativeNamecoinArchiveFailure.abi(raw)!.code) { try state.returned(raw) } }
                initRefusal("outcome_unknown") { try state.begin() }
                initRefusal("outcome_unknown") { try state.requireCompleted() }
                // Complete refusal/panic never consumes Close ownership here.
                #expect(state.phase != .closed)
            }
            #expect(events.last == "native-public-fixture-clear")
            #expect(ownership.takeForClose() == 7)
            events.append("explicit-close")
            #expect(ownership.takeForClose() == nil)
            state.close()
            #expect(events.last == "explicit-close")
        }
    }

    // Pure public handle admission: low nonzero init domain, exact error codes.
    // This establishes no registry ownership or kernel exclusion.
    @Test func handleDomainAndPreCompletionRefusals() throws {
        try NativeInitializationABI.opened(0, handle: 7)
        for handle in [UInt64(0), UInt64(1) << 63, (UInt64(1) << 63) | 7] {
            initRefusal("outcome_unknown") { try NativeInitializationABI.opened(0, handle: handle) }
        }
        initRefusal("account_busy") { try NativeInitializationABI.opened(13, handle: 0) }
        initRefusal("outcome_unknown") { try NativeInitializationABI.opened(13, handle: 7) }
        initRefusal("outcome_unknown") { try NativeInitializationABI.opened(999, handle: 0) }
        var state = NativeInitializationLifecycle()
        initRefusal("outcome_unknown") { try state.requireCompleted() }
        state.close()
        initRefusal("outcome_unknown") { try state.begin() }
    }

    // Real C negative controls stop BEFORE any production home reservation:
    // malformed config18; mismatched pin5. Unknown Close never opens a session.
    // Valid Open/Complete is NOT_RUN in automated native lanes. Separate Go
    // fixtures cover isolated actual temporary-gate/panic controls.
    @Test func actualCPreReservationRefusalsOnly() throws {
        var bad = Array(Data("null".utf8)), handle: UInt64 = 99
        let raw = bad.withUnsafeMutableBufferPointer {
            kv_nmc_init_open_v1(nil, 0, $0.baseAddress, size_t($0.count), &handle)
        }
        #expect(raw == 18)
        #expect(handle == 0)
        #expect(kv_nmc_init_open_v1(nil, 0, nil, 0, nil) == 1)
        let fixture = try InitializationFixture()
        var config = Array(fixture.config), wrongPin = Array(Data("wrong public pin".utf8))
        handle = 99
        let mismatch = wrongPin.withUnsafeMutableBufferPointer { pin in
            config.withUnsafeMutableBufferPointer { config in
                kv_nmc_init_open_v1(pin.baseAddress, size_t(pin.count), config.baseAddress, size_t(config.count), &handle)
            }
        }
        #expect(mismatch == 5)
        #expect(handle == 0)
        #expect(Data(config) == fixture.config)
        #expect(Data(wrongPin) == Data("wrong public pin".utf8))
        #expect(Data(bad) == Data("null".utf8))
        #expect(kv_nmc_init_close_v1(0) == 1)
        #expect(kv_nmc_init_close_v1(UInt64.max) == 1)
    }
}

// SOURCE / NOT_RUN: public query status and ordering controls. Synthetic states
// do not attest actual gate retention, native absence, account cleanup or TouchID.
// No test invokes valid production init Open, Complete, withAccount or Keychain.
extension NamecoinInitializationArchiveBridgeTests {
    // Positive query/requery after native rechecks beside denied early Complete
    // and early query. Only actual production C query results reach this state
    // in the bridge; injecting raw0 here proves software ordering alone.
    @Test func publicAbsenceSuccessIsRequiredBeforeCompletion() throws {
        var earlyComplete = NativeInitializationLifecycle()
        initRefusal("outcome_unknown") { try earlyComplete.begin() }
        #expect(earlyComplete.phase == .refused)
        var earlyQuery = NativeInitializationLifecycle()
        initRefusal("outcome_unknown") { try earlyQuery.absenceReturned(0) }
        #expect(earlyQuery.phase == .refused)
        initRefusal("outcome_unknown") { try earlyQuery.nativeRechecked() }

        var state = NativeInitializationLifecycle()
        try state.nativeRechecked()
        #expect(state.phase == .nativeRechecked)
        try state.requireAbsenceQuery()
        try state.absenceReturned(0)
        #expect(state.phase == .publicAbsent)
        try state.absenceReturned(0) // Read-only successful query may repeat.
        #expect(state.phase == .publicAbsent)
        try state.begin()
        #expect(state.phase == .completing)
        try state.returned(0)
        try state.requireCompleted()
        #expect(state.phase == .completed)
        state.close()
        initRefusal("outcome_unknown") { try state.absenceReturned(0) }
        #expect(state.phase == .closed)
    }

    // Literal invalid/closed1, consumed/panic19, unavailable20 and unknown-code
    // mapping, with no resurrection after a later raw0. These are status/state
    // controls; consumed/closed actual-handle and panic/gate proofs remain Go
    // fixture/native lanes, not a synthesized native-success assertion here.
    @Test func absenceRefusalsLatchAndNeverAdmitLaterSuccess() throws {
        let cases: [(Int32, String)] = [(1, "invalid_request"), (19, "outcome_unknown"),
                                       (20, "journal_unavailable"), (-1, "outcome_unknown"),
                                       (22, "outcome_unknown"), (Int32.min, "outcome_unknown"),
                                       (Int32.max, "outcome_unknown")]
        for (raw, expected) in cases {
            var state = NativeInitializationLifecycle()
            var ownership = try NativeArchiveHandleOwnership(7)
            try state.nativeRechecked()
            initRefusal(expected) { try state.absenceReturned(raw) }
            #expect(state.phase == .refused)
            initRefusal("outcome_unknown") { try state.absenceReturned(0) }
            initRefusal("outcome_unknown") { try state.begin() }
            initRefusal("outcome_unknown") { try state.requireCompleted() }
            #expect(state.phase == .refused)
            // Query failure does not take software Close ownership. This token
            // is not a real kernel listener or evidence of kernel retention.
            #expect(ownership.takeForClose() == 7)
            #expect(ownership.takeForClose() == nil)
            state.close()
        }
    }

    // Bounded fixture sequence calls the actual lifecycle predicates used in
    // production. A PUBLIC marker stands in for a borrow; no account/private
    // closure, C Complete, protected callback or real gate is invoked. Counters
    // prove this synthetic sequence only; exact production entry ordering also
    // needs the source witness and later native integration. NOT_RUN.
    @Test func syntheticQueryControlsBorrowAndClearBeforeClose() throws {
        let cases: [(query: Int32, complete: Int32, expected: String?)] = [
            (0, 0, nil), (0, 19, "outcome_unknown"), (0, 20, "journal_unavailable"),
            (1, 0, "invalid_request"), (19, 0, "outcome_unknown"),
            (20, 0, "journal_unavailable"), (999, 0, "outcome_unknown")
        ]
        for item in cases {
            var state = NativeInitializationLifecycle()
            var ownership = try NativeArchiveHandleOwnership(7)
            var borrows = 0, completes = 0, events = ["native-rechecks"]
            try state.nativeRechecked()
            let attempt = {
                events.append("public-query")
                try state.absenceReturned(item.query)
                events.append("public-borrow-start"); borrows += 1
                let marker = [UInt8](repeating: 0x42, count: 64)
                let owned = try marker.withUnsafeBytes { try NativeSecretBytes(copying: $0, maximum: 64) }
                defer { owned.clear(); events.append("public-fixture-cleared") }
                try state.begin()
                completes += 1; events.append("synthetic-complete")
                try state.returned(item.complete)
            }
            if let expected = item.expected { initRefusal(expected) { try attempt() } }
            else { try attempt(); try state.requireCompleted() }
            if item.query == 0 {
                #expect(borrows == 1 && completes == 1)
                #expect(events == ["native-rechecks", "public-query", "public-borrow-start", "synthetic-complete", "public-fixture-cleared"])
            } else {
                #expect(borrows == 0 && completes == 0)
                #expect(events == ["native-rechecks", "public-query"])
            }
            #expect(state.phase != .closed) // No query/Complete path closes.
            #expect(ownership.takeForClose() == 7)
            events.append("explicit-close"); state.close()
            #expect(events.last == "explicit-close")
            #expect(ownership.takeForClose() == nil)
            #expect(NativeInitializationABI.closeResult(19)?.code == "outcome_unknown")
        }
    }

    // Actual imported C query only for provably invalid zero/ROOT-domain
    // handles: no valid initialization handle or production home is opened.
    // Positive real query/consumed/closed/gate lanes need isolated Go fixtures
    // or separately admitted native execution, not a valid-home test here.
    @Test func actualAbsenceQueryRejectsInvalidDomainsWithoutOpeningHome() {
        for handle in [UInt64(0), UInt64(1) << 63, UInt64.max] {
            #expect(kv_nmc_init_check_absent_v1(handle) == 1)
            #expect(kv_nmc_init_check_absent_v1(handle) == 1)
            #expect(kv_nmc_init_close_v1(handle) == 1)
        }
    }
}
