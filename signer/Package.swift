// swift-tools-version:6.0
// The trusted signer core (ADR 0006, ADR 0007): strict payload parsing, the
// display model, the decision to sign or deny, keys and the TOFU host store.
// Apple frameworks only; the menu bar app and the SSH transport build on it.
import PackageDescription

let package = Package(
    name: "TMBSigner",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "SignerCore", targets: ["SignerCore"]),
    ],
    targets: [
        .target(name: "SignerCore"),
        .testTarget(name: "SignerCoreTests", dependencies: ["SignerCore"]),
    ],
    swiftLanguageModes: [.v6]
)
