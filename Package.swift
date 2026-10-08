// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "Virux",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "ViruxCore", targets: ["ViruxCore"]),
        .library(name: "ViruxIPC", targets: ["ViruxIPC"]),
        .library(name: "ViruxSensor", targets: ["ViruxSensor"]),
        .library(name: "ViruxDetect", targets: ["ViruxDetect"]),
        .library(name: "ViruxSandbox", targets: ["ViruxSandbox"]),
        .executable(name: "viruxd", targets: ["viruxd"]),
        .executable(name: "virux", targets: ["virux"]),
        .executable(name: "ViruxMenuBar", targets: ["ViruxMenuBar"]),
    ],
    targets: [
        .target(name: "ViruxCore"),
        .target(name: "ViruxIPC", dependencies: ["ViruxCore"]),
        .target(name: "ViruxSensor", dependencies: ["ViruxCore"]),
        .target(name: "ViruxDetect", dependencies: ["ViruxCore"]),
        .target(name: "ViruxSandbox", dependencies: ["ViruxCore", "ViruxDetect"]),
        .executableTarget(name: "viruxd", dependencies: ["ViruxCore", "ViruxSensor", "ViruxIPC", "ViruxDetect"]),
        .executableTarget(name: "virux", dependencies: ["ViruxCore", "ViruxSensor", "ViruxIPC", "ViruxDetect", "ViruxSandbox"]),
        .executableTarget(name: "ViruxMenuBar", dependencies: ["ViruxCore", "ViruxIPC"]),
        .testTarget(name: "ViruxCoreTests", dependencies: ["ViruxCore"]),
        .testTarget(name: "ViruxSensorTests", dependencies: ["ViruxSensor"]),
        .testTarget(name: "ViruxDetectTests", dependencies: ["ViruxDetect"]),
        .testTarget(name: "ViruxSandboxTests", dependencies: ["ViruxSandbox"]),
    ]
)