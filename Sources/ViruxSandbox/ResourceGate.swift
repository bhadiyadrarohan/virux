import Foundation
import Darwin

/// A snapshot of the host resources the sandbox cares about.
public struct SystemResources: Sendable {
    public var freeMemoryBytes: UInt64
    public var freeDiskBytes: UInt64

    public init(freeMemoryBytes: UInt64, freeDiskBytes: UInt64) {
        self.freeMemoryBytes = freeMemoryBytes
        self.freeDiskBytes = freeDiskBytes
    }

    public var freeMemoryGB: Double { Double(freeMemoryBytes) / 1_073_741_824 }
    public var freeDiskGB: Double { Double(freeDiskBytes) / 1_073_741_824 }
}

public protocol ResourceProbe: AnyObject {
    func sample() -> SystemResources
}

/// Reads real host free memory and free disk. Free memory uses the VM
/// statistics (free + inactive + speculative), which tracks macOS pressure
/// better than "free" alone.
public final class SystemResourceProbe: ResourceProbe {
    public init() {}

    public func sample() -> SystemResources {
        SystemResources(freeMemoryBytes: Self.freeMemory(), freeDiskBytes: Self.freeDisk())
    }

    static func freeMemory() -> UInt64 {
        var stats = vm_statistics64_data_t()
        var count = mach_msg_type_number_t(
            MemoryLayout<vm_statistics64_data_t>.size / MemoryLayout<integer_t>.size)
        let result = withUnsafeMutablePointer(to: &stats) { ptr -> kern_return_t in
            ptr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { intPtr in
                host_statistics64(mach_host_self(), HOST_VM_INFO64, intPtr, &count)
            }
        }
        guard result == KERN_SUCCESS else { return 0 }
        let pageSize = UInt64(getpagesize())
        let pages = UInt64(stats.free_count) + UInt64(stats.inactive_count) + UInt64(stats.speculative_count)
        return pages * pageSize
    }

    static func freeDisk() -> UInt64 {
        var st = statfs()
        guard statfs("/", &st) == 0 else { return 0 }
        return UInt64(st.f_bavail) * UInt64(st.f_bsize)
    }
}

public struct GateConfig: Sendable {
    public var minFreeMemoryBytes: UInt64
    public var minFreeDiskBytes: UInt64
    public var maxConcurrentRuns: Int

    public init(minFreeMemoryBytes: UInt64 = 4 * 1_073_741_824,
                minFreeDiskBytes: UInt64 = 8 * 1_073_741_824,
                maxConcurrentRuns: Int = 1) {
        self.minFreeMemoryBytes = minFreeMemoryBytes
        self.minFreeDiskBytes = minFreeDiskBytes
        self.maxConcurrentRuns = maxConcurrentRuns
    }
}

public enum GateDecision: Equatable, Sendable {
    case allow
    case deferred(reason: String)

    public var isAllowed: Bool { if case .allow = self { return true }; return false }
}

/// Decides whether a VM sandbox run may start. Never force-launches: if the
/// host is short on RAM, on disk, or already running the max number of VMs,
/// the run is deferred with an explicit reason.
public struct ResourceGate: Sendable {
    public let config: GateConfig
    public init(config: GateConfig = GateConfig()) { self.config = config }

    public func decide(resources: SystemResources, activeRuns: Int) -> GateDecision {
        if activeRuns >= config.maxConcurrentRuns {
            return .deferred(reason: "max concurrent runs reached (\(config.maxConcurrentRuns))")
        }
        if resources.freeMemoryBytes < config.minFreeMemoryBytes {
            return .deferred(reason: String(format: "free memory %.2f GB < %.2f GB required",
                                            resources.freeMemoryGB, Double(config.minFreeMemoryBytes) / 1_073_741_824))
        }
        if resources.freeDiskBytes < config.minFreeDiskBytes {
            return .deferred(reason: String(format: "free disk %.2f GB < %.2f GB required",
                                            resources.freeDiskGB, Double(config.minFreeDiskBytes) / 1_073_741_824))
        }
        return .allow
    }
}
