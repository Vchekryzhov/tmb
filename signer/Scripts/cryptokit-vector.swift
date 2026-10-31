// Adds CryptoKit-made signature vectors to Tests/vectors/approval-v1.json,
// so the Go tests prove crypto/ecdsa.VerifyASN1 accepts what CryptoKit
// signs (the Secure Enclave signs with the same algorithm and DER form).
// The key is a throwaway software key; only its public half is kept.
//
//   swift signer/Scripts/cryptokit-vector.swift signer/Tests/vectors/approval-v1.json
import CryptoKit
import Foundation

let path = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "signer/Tests/vectors/approval-v1.json"
let url = URL(fileURLWithPath: path)
var root = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
let valid = root["valid"] as! [[String: Any]]
let sample = Data(base64Encoded: valid[0]["payload"] as! String)!
let tricky = Data(base64Encoded: valid[1]["payload"] as! String)!

let key = P256.Signing.PrivateKey()
let sig = try key.signature(for: sample)
let pub = key.publicKey.derRepresentation.base64EncodedString()

var sigs = (root["signatures"] as? [[String: Any]] ?? []).filter { ($0["source"] as? String) != "cryptokit" }
sigs.append(["name": "cryptokit signature over sample", "source": "cryptokit", "public_key": pub,
             "payload": sample.base64EncodedString(), "signature": sig.derRepresentation.base64EncodedString(), "valid": true])
sigs.append(["name": "cryptokit signature checked against another payload", "source": "cryptokit", "public_key": pub,
             "payload": tricky.base64EncodedString(), "signature": sig.derRepresentation.base64EncodedString(), "valid": false])
root["signatures"] = sigs
let out = try JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
try (out + Data("\n".utf8)).write(to: url)
print("added \(2) CryptoKit signature vectors to \(path)")
