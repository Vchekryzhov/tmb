// swift-tools-version:6.0
// The trusted signer (ADR 0006, ADR 0007). SignerCore: strict payload
// parsing, the display model, the decision to sign or deny, keys and the
// TOFU host store. SignerService: the SSH transport to `tmb approve`, the
// polling workflow, the Mac-side config and the process integrity checks.
// TMBSigner: the menu bar app. Apple frameworks only.
import PackageDescription

let package = Package(
    name: "TMBSigner",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "SignerCore", targets: ["SignerCore"]),
        .library(name: "SignerService", targets: ["SignerService"]),
        .executable(name: "TMBSigner", targets: ["TMBSigner"]),
    ],
    targets: [
        .target(name: "SignerCore"),
        .target(name: "SignerService", dependencies: ["SignerCore"]),
        .executableTarget(name: "TMBSigner", dependencies: ["SignerCore", "SignerService"]),
        .testTarget(name: "SignerCoreTests", dependencies: ["SignerCore"]),
        .testTarget(name: "SignerServiceTests", dependencies: ["SignerService", "SignerCore"],
                    exclude: ["recorded"]),
    ],
    swiftLanguageModes: [.v6]
)
