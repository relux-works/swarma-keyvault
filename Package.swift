// swift-tools-version: 6.0
import Foundation
import PackageDescription

let manifestRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
// This selector is a public BUILD INPUT, never runtime/account authority.
// The Go builder validates the source/pair receipt before and after compilation.
let archiveDirectory = ProcessInfo.processInfo.environment["KEYVAULT_NATIVE_ARCHIVE_DIR"]
    ?? ".temp/namecoin-native-archive"
let inputPattern = #"^\.temp/(native-archive-[a-f0-9]{32}|namecoin-native-archive)$"#
precondition(archiveDirectory.range(of: inputPattern, options: .regularExpression)
                == (archiveDirectory.startIndex..<archiveDirectory.endIndex),
             "invalid native archive directory")
let archiveRoot = manifestRoot.appendingPathComponent(archiveDirectory)
precondition(archiveRoot.resolvingSymlinksInPath().path == archiveRoot.path,
             "native archive directory must not contain symlinks")
let nativeArchive = archiveRoot.appendingPathComponent("libkeyvault_namecoin.a").path

let coreSources = [
    "NativeHelperCore.swift",
    "NamecoinBiometryPolicy.swift",
    "NamecoinJournalStorage.swift",
    "NamecoinJournalOperations.swift",
    "NamecoinPrivateOutput.swift",
    "NamecoinArchiveBridge.swift",
    "NamecoinInitializationArchiveBridge.swift",
    "RootGrantsReview.swift",
    "RootGrantsArchiveBridge.swift",
    "RootGrantsPrivate.swift",
    "RootGrantsSignV3.swift",
    "RootGrantsQualification.swift",
]
let testSources = [
    "NamecoinJournalStorageTests.swift",
    "NamecoinReviewSnapshotTests.swift",
    "NamecoinPrivateOutputTests.swift",
    "NamecoinArchiveBridgeTests.swift",
    "NamecoinInitializationArchiveBridgeTests.swift",
    "NamecoinBiometryPolicyTests.swift",
    "RootGrantsReviewTests.swift",
    "RootGrantsArchiveBridgeTests.swift",
    "RootGrantsPrivateTests.swift",
    "RootGrantsSignV3Tests.swift",
    "RootGrantsQualificationTests.swift",
]

// Explicit, disjoint source lists keep the executable dispatcher out of the
// imported production core and normal Swift Testing discovery. The generated
// header/archive must be staged together; missing inputs are real build errors.
let package = Package(
    name: "KeyvaultNative",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "mac-keyvault-enclave", targets: ["KeyvaultNativeExecutable"]),
    ],
    dependencies: [],
    targets: [
        .systemLibrary(
            name: "NamecoinArchiveABI",
            path: archiveDirectory
        ),
        .target(
            name: "KeyvaultNativeCore",
            dependencies: ["NamecoinArchiveABI"],
            path: "cmd/mac-keyvault-enclave",
            exclude: ["main.swift"] + testSources,
            sources: coreSources,
            linkerSettings: [
                .unsafeFlags([nativeArchive]),
                .linkedFramework("Security"),
                .linkedFramework("CoreFoundation"),
            ]
        ),
        .executableTarget(
            name: "KeyvaultNativeExecutable",
            dependencies: ["KeyvaultNativeCore"],
            path: "cmd/mac-keyvault-enclave",
            exclude: coreSources + testSources,
            sources: ["main.swift"]
        ),
        .testTarget(
            name: "NamecoinNativeTests",
            dependencies: ["KeyvaultNativeCore", "NamecoinArchiveABI"],
            path: "cmd/mac-keyvault-enclave",
            exclude: ["main.swift"] + coreSources,
            sources: testSources,
            linkerSettings: [.linkedLibrary("util")]
        ),
    ],
    swiftLanguageModes: [.v5]
)
