import Foundation

/// Result of static (no-execution) inspection of a candidate sample.
/// A clean static result is NOT proof of safety, and neither is a clean
/// sandbox run; that is why `verdict` is separate from `reasons`.
public enum StaticVerdict: String, Sendable {
    case clean, inconclusive, suspicious
}

public struct MachOFindings: Sendable {
    public var path: String
    public var sizeBytes: Int64
    public var isMachO: Bool
    public var isFat: Bool
    public var architectures: [String]
    public var fileType: String?
    public var hasCodeSignature: Bool
    public var isEncrypted: Bool
    public var linkedLibraries: [String]
    public var suspiciousStrings: [String]
    public var entropy: Double
    public var verdict: StaticVerdict
    public var reasons: [String]
}

public enum MachOError: Error, CustomStringConvertible {
    case unreadable(String)
    public var description: String {
        switch self { case .unreadable(let p): return "cannot read \(p)" }
    }
}

/// Extremely lightweight Mach-O inspection: header, load commands (code
/// signature, dylibs, encryption), embedded strings, and entropy. No execution,
/// no disassembly. Deliberately conservative and dependency-free.
public enum MachOAnalyzer {

    private static let maxScanBytes = 64 * 1024 * 1024

    public static func analyze(path: String) throws -> MachOFindings {
        guard let data = readUpTo(path: path, maxBytes: maxScanBytes) else {
            throw MachOError.unreadable(path)
        }
        var findings = MachOFindings(
            path: path, sizeBytes: Int64(data.count), isMachO: false, isFat: false,
            architectures: [], fileType: nil, hasCodeSignature: false,
            isEncrypted: false, linkedLibraries: [], suspiciousStrings: [],
            entropy: entropy(of: data), verdict: .inconclusive, reasons: [])

        guard data.count >= 4 else {
            findings.reasons.append("file too small to be a Mach-O")
            return findings
        }

        switch u32(data, 0) {
        case 0xFEEDFACF: // MH_MAGIC_64, little-endian (arm64 / x86_64)
            parseThin(data, offset: 0, into: &findings)
        case 0xCFFAEDFE: // byte-swapped: big-endian Mach-O (rare)
            findings.isMachO = true
            findings.reasons.append("big-endian Mach-O (uncommon)")
        default:
            // Fat/universal binaries store their fat header big-endian.
            switch u32be(data, 0) {
            case 0xCAFEBABE: // FAT_MAGIC (32-bit offsets)
                findings.isMachO = true
                findings.isFat = true
                parseFat(data, into: &findings, wide: false)
            case 0xCAFEBABF: // FAT_MAGIC_64 (64-bit offsets)
                findings.isMachO = true
                findings.isFat = true
                parseFat(data, into: &findings, wide: true)
            default:
                findings.reasons.append("not a Mach-O binary")
            }
        }

        finalize(&findings)
        return findings
    }

    // MARK: - Parsing

    private static func parseFat(_ data: Data, into f: inout MachOFindings, wide: Bool) {
        let nfat = u32be(data, 4)
        guard nfat > 0, nfat < 64 else { f.reasons.append("implausible fat header"); return }
        var off = 8
        for _ in 0..<nfat {
            guard off + (wide ? 32 : 20) <= data.count else { break }
            let cpuType = u32be(data, off)
            let sliceOffset = wide ? Int(u64be(data, off + 8)) : Int(u32be(data, off + 8))
            f.architectures.append(archName(cpuType))
            if sliceOffset > 0, sliceOffset + 32 <= data.count, u32(data, sliceOffset) == 0xFEEDFACF {
                parseThin(data, offset: sliceOffset, into: &f)
            }
            off += (wide ? 32 : 20)
        }
    }

    private static func parseThin(_ data: Data, offset: Int, into f: inout MachOFindings) {
        guard offset + 32 <= data.count else { return }
        f.isMachO = true
        let cpuType = u32(data, offset + 4)
        let fileType = u32(data, offset + 12)
        let ncmds = u32(data, offset + 16)
        if !f.architectures.contains(archName(cpuType)) { f.architectures.append(archName(cpuType)) }
        f.fileType = fileTypeName(fileType)

        var cmdOff = offset + 32
        var processed = 0
        while processed < Int(ncmds), cmdOff + 8 <= data.count, processed < 4096 {
            let cmd = u32(data, cmdOff)
            let cmdsize = u32(data, cmdOff + 4)
            guard cmdsize >= 8 else { break }
            switch cmd {
            case 0x1D: // LC_CODE_SIGNATURE
                f.hasCodeSignature = true
            case 0x2C: // LC_ENCRYPTION_INFO_64
                if cmdOff + 16 <= data.count, u32(data, cmdOff + 12) != 0 { f.isEncrypted = true }
            case 0x0C, 0x80000018, 0x18: // LC_LOAD_DYLIB / weak
                if cmdOff + 24 <= data.count { f.linkedLibraries.append(readCString(data, at: cmdOff + 24, max: Int(cmdsize) - 24) ?? "?") }
            default:
                break
            }
            cmdOff += Int(cmdsize)
            processed += 1
        }

        f.suspiciousStrings = scanStrings(data)
    }

    private static func finalize(_ f: inout MachOFindings) {
        f.architectures = dedupe(f.architectures)
        f.linkedLibraries = dedupe(f.linkedLibraries)
        if !f.isMachO {
            f.verdict = .inconclusive
            return
        }
        if f.isEncrypted {
            f.reasons.append("binary is encrypted (LC_ENCRYPTION_INFO)")
        }
        if !f.hasCodeSignature {
            f.reasons.append("no code signature (LC_CODE_SIGNATURE absent)")
        }
        if !f.suspiciousStrings.isEmpty {
            f.reasons.append("suspicious embedded strings: \(f.suspiciousStrings.prefix(5).joined(separator: ", "))")
        }
        if f.entropy > 7.2 {
            f.reasons.append(String(format: "high entropy (%.2f) suggests packing or encryption", f.entropy))
        }

        if f.isEncrypted || !f.hasCodeSignature || !f.suspiciousStrings.isEmpty {
            f.verdict = .suspicious
        } else if f.entropy > 7.2 {
            f.verdict = .inconclusive
        } else {
            f.verdict = .clean
        }
        if f.reasons.isEmpty { f.reasons.append("no static red flags observed") }
    }

    // MARK: - Strings and entropy

    private static let patterns = ["/bin/sh", "/bin/bash", "/bin/zsh", "osascript",
                                   "LaunchDaemons", "LaunchAgents", "/etc/passwd",
                                   ".onion", "base64 -d", "nc -e", "chmod 777", "eval $("]

    private static func scanStrings(_ data: Data) -> [String] {
        var found = Set<String>()
        var current = [UInt8]()
        let limit = min(data.count, 8 * 1024 * 1024)
        data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            let bytes = raw.bindMemory(to: UInt8.self)
            for i in 0..<limit {
                let b = bytes[i]
                if b >= 32 && b < 127 {
                    current.append(b)
                    if current.count > 256 { current.removeAll(keepingCapacity: true) }
                } else {
                    if current.count >= 6 {
                        let s = String(decoding: current, as: UTF8.self)
                        for p in patterns where s.contains(p) {
                            if found.count < 32 { found.insert(p) }
                        }
                    }
                    current.removeAll(keepingCapacity: true)
                }
            }
        }
        if current.count >= 6 {
            let s = String(decoding: current, as: UTF8.self)
            for p in patterns where s.contains(p) { if found.count < 32 { found.insert(p) } }
        }
        return found.sorted()
    }

    private static func dedupe(_ items: [String]) -> [String] {
        var seen = Set<String>()
        var out: [String] = []
        for i in items where !seen.contains(i) { seen.insert(i); out.append(i) }
        return out
    }

    private static func entropy(of data: Data) -> Double {
        guard !data.isEmpty else { return 0 }
        let limit = min(data.count, 8 * 1024 * 1024)
        var counts = [Int](repeating: 0, count: 256)
        data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            let bytes = raw.bindMemory(to: UInt8.self)
            for i in 0..<limit { counts[Int(bytes[i])] += 1 }
        }
        let total = Double(limit)
        var h = 0.0
        for c in counts where c > 0 {
            let p = Double(c) / total
            h -= p * log2(p)
        }
        return h
    }

    // MARK: - Byte helpers

    private static func u32(_ data: Data, _ offset: Int) -> UInt32 {
        guard offset + 4 <= data.count else { return 0 }
        return data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self) }.littleEndian
    }

    /// Big-endian u32, used for the fat/universal binary header (which is
    /// stored big-endian regardless of the host).
    private static func u32be(_ data: Data, _ offset: Int) -> UInt32 {
        guard offset + 4 <= data.count else { return 0 }
        let v = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self) }
        return UInt32(bigEndian: v)
    }

    private static func u64be(_ data: Data, _ offset: Int) -> UInt64 {
        guard offset + 8 <= data.count else { return 0 }
        let v = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt64.self) }
        return UInt64(bigEndian: v)
    }

    private static func readCString(_ data: Data, at offset: Int, max: Int) -> String? {
        guard offset < data.count, max > 0 else { return nil }
        let end = min(offset + max, data.count)
        var bytes = [UInt8]()
        var i = offset
        while i < end, data[i] != 0, bytes.count < 512 { bytes.append(data[i]); i += 1 }
        return bytes.isEmpty ? nil : String(decoding: bytes, as: UTF8.self)
    }

    private static func readUpTo(path: String, maxBytes: Int) -> Data? {
        guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? handle.close() }
        return handle.readData(ofLength: maxBytes)
    }

    private static func archName(_ cpuType: UInt32) -> String {
        switch cpuType {
        case 0x0100000C: return "arm64"
        case 0x01000007: return "x86_64"
        case 0x00000007: return "i386"
        case 0x0000000C: return "arm"
        default: return String(format: "cpu(0x%08x)", cpuType)
        }
    }

    private static func fileTypeName(_ fileType: UInt32) -> String {
        switch fileType {
        case 1: return "MH_OBJECT"
        case 2: return "MH_EXECUTE"
        case 6: return "MH_DYLIB"
        case 8: return "MH_BUNDLE"
        case 10: return "MH_DSYM"
        default: return "type(\(fileType))"
        }
    }
}
