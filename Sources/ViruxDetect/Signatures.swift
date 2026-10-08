import Foundation
import CryptoKit
import ViruxCore

/// A single known-bad (or known-good) hash entry.
public struct SignatureEntry: Codable, Sendable, Equatable {
    public var sha256: String
    public var name: String
    public var severity: Severity

    public init(sha256: String, name: String, severity: Severity) {
        self.sha256 = sha256.lowercased()
        self.name = name
        self.severity = severity
    }
}

/// The payload of a signature update: a versioned list of entries.
public struct SignatureBundle: Codable, Sendable {
    public var version: Int
    public var generatedAt: Date
    public var entries: [SignatureEntry]

    public init(version: Int = 1, generatedAt: Date = Date(), entries: [SignatureEntry]) {
        self.version = version
        self.generatedAt = generatedAt
        self.entries = entries
    }
}

/// The on-disk, signed form: the canonical payload bytes plus a detached
/// Ed25519 signature. Signing the exact bytes (base64-encoded) avoids any
/// canonical-JSON ambiguity at verification time.
public struct SignedBundle: Codable, Sendable {
    public var payload: String
    public var signature: String
}

public enum SignatureError: Error, CustomStringConvertible {
    case malformed(String)
    case badSignature

    public var description: String {
        switch self {
        case .malformed(let m): return "malformed bundle: \(m)"
        case .badSignature: return "signature verification failed"
        }
    }
}

/// Ed25519 signing and verification of signature bundles (CryptoKit). Update
/// bundles are verify-before-apply; a failed verification is a hard stop.
public enum SignatureSigner {

    public static func canonicalPayload(_ bundle: SignatureBundle) throws -> Data {
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys]
        enc.dateEncodingStrategy = .secondsSince1970
        return try enc.encode(bundle)
    }

    /// Signs a bundle and returns the serialized signed envelope.
    public static func sign(_ bundle: SignatureBundle,
                            privateKey: Curve25519.Signing.PrivateKey) throws -> Data {
        let payload = try canonicalPayload(bundle)
        let signature = try privateKey.signature(for: payload)
        let envelope = SignedBundle(payload: payload.base64EncodedString(),
                                    signature: signature.base64EncodedString())
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys]
        return try enc.encode(envelope)
    }

    /// Verifies and opens a signed envelope. Throws on any tampering.
    public static func open(_ data: Data,
                            publicKey: Curve25519.Signing.PublicKey) throws -> SignatureBundle {
        let envelope: SignedBundle
        do {
            envelope = try JSONDecoder().decode(SignedBundle.self, from: data)
        } catch {
            throw SignatureError.malformed("not a signed bundle")
        }
        guard let payload = Data(base64Encoded: envelope.payload),
              let signature = Data(base64Encoded: envelope.signature) else {
            throw SignatureError.malformed("bad base64 in payload or signature")
        }
        guard publicKey.isValidSignature(signature, for: payload) else {
            throw SignatureError.badSignature
        }
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .secondsSince1970
        return try dec.decode(SignatureBundle.self, from: payload)
    }

    /// Generates a fresh key pair (used to bootstrap signing infra; the real
    /// private key stays offline, per DECISIONS).
    public static func generateKeyPair() -> (privateKey: Curve25519.Signing.PrivateKey,
                                             publicKey: Curve25519.Signing.PublicKey) {
        let priv = Curve25519.Signing.PrivateKey()
        return (priv, priv.publicKey)
    }
}

/// Fast, in-memory lookup of hashes to entries, built from a verified bundle.
public final class SignatureMatcher {
    private var map: [String: SignatureEntry]

    public init(bundle: SignatureBundle) {
        var m: [String: SignatureEntry] = [:]
        for e in bundle.entries { m[e.sha256.lowercased()] = e }
        self.map = m
    }

    public func lookup(_ hash: String) -> SignatureEntry? {
        map[hash.lowercased()]
    }

    public var count: Int { map.count }
}
