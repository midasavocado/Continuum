// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "Continuum",
    platforms: [
        .macOS(.v15)
    ],
    products: [
        .library(name: "ContinuumCore", targets: ["ContinuumCore"]),
        .library(name: "ContinuumStore", targets: ["ContinuumStore"]),
        .library(name: "ContinuumSystem", targets: ["ContinuumSystem"]),
        .library(name: "ContinuumRuntime", targets: ["ContinuumRuntime"]),
        .library(
            name: "ContinuumBootstrap",
            type: .dynamic,
            targets: ["ContinuumBootstrap"]
        ),
        .executable(name: "ContinuumTerminalRelay", targets: ["ContinuumTerminalRelay"]),
        .executable(name: "ContinuumManagedExec", targets: ["ContinuumManagedExec"]),
        .executable(name: "Continuum", targets: ["ContinuumApp"]),
        .executable(name: "ContinuumHarness", targets: ["ContinuumHarness"]),
        .executable(name: "ContinuumExternalTarget", targets: ["ContinuumExternalTarget"]),
        .executable(name: "ContinuumGUIExternalTarget", targets: ["ContinuumGUIExternalTarget"])
    ],
    targets: [
        .target(name: "ContinuumCore"),
        .target(
            name: "ContinuumStore",
            dependencies: ["ContinuumCore"],
            linkerSettings: [.linkedFramework("Security")]
        ),
        .target(
            name: "ContinuumRuntime",
            publicHeadersPath: "include",
            linkerSettings: [.linkedFramework("Security")]
        ),
        .target(
            name: "ContinuumBootstrap",
            publicHeadersPath: "include",
            linkerSettings: [
                .linkedFramework("CoreFoundation"),
                .linkedLibrary("objc")
            ]
        ),
        .target(name: "ContinuumTerminalRelayCore", publicHeadersPath: "include"),
        .executableTarget(
            name: "ContinuumTerminalRelay",
            dependencies: ["ContinuumTerminalRelayCore"]
        ),
        .executableTarget(name: "ContinuumManagedExec"),
        .target(
            name: "ContinuumSystem",
            dependencies: [
                "ContinuumCore",
                "ContinuumRuntime",
                "ContinuumStore",
                "ContinuumTerminalRelayCore"
            ],
            linkerSettings: [
                .linkedFramework("ApplicationServices"),
                .linkedFramework("Security")
            ]
        ),
        .executableTarget(
            name: "ContinuumApp",
            dependencies: ["ContinuumCore", "ContinuumStore", "ContinuumSystem"]
        ),
        .executableTarget(
            name: "ContinuumHarness",
            dependencies: ["ContinuumCore", "ContinuumStore", "ContinuumSystem", "ContinuumRuntime"]
        ),
        .executableTarget(name: "ContinuumExternalTarget"),
        .target(
            name: "ContinuumGUIStateSupport",
            publicHeadersPath: "include"
        ),
        .executableTarget(
            name: "ContinuumGUIExternalTarget",
            dependencies: ["ContinuumGUIStateSupport"],
            linkerSettings: [.linkedFramework("AppKit")]
        ),
        .testTarget(name: "ContinuumCoreTests", dependencies: ["ContinuumCore"]),
        .testTarget(name: "ContinuumStoreTests", dependencies: ["ContinuumCore", "ContinuumStore"]),
        .testTarget(
            name: "ContinuumSystemTests",
            dependencies: ["ContinuumCore", "ContinuumSystem", "ContinuumTerminalRelayCore"]
        ),
        .testTarget(
            name: "ContinuumRuntimeTests",
            dependencies: ["ContinuumRuntime", "ContinuumBootstrap"]
        ),
        .testTarget(
            name: "ContinuumManagedExecTests",
            dependencies: ["ContinuumManagedExec"]
        ),
        .testTarget(name: "ContinuumAppTests", dependencies: ["ContinuumApp", "ContinuumSystem"])
    ]
)
