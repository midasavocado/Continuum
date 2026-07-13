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
        .executable(name: "Continuum", targets: ["ContinuumApp"]),
        .executable(name: "ContinuumHarness", targets: ["ContinuumHarness"]),
        .executable(name: "ContinuumExternalTarget", targets: ["ContinuumExternalTarget"])
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
            publicHeadersPath: "include"
        ),
        .target(
            name: "ContinuumSystem",
            dependencies: ["ContinuumCore", "ContinuumRuntime", "ContinuumStore"],
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
        .testTarget(name: "ContinuumCoreTests", dependencies: ["ContinuumCore"]),
        .testTarget(name: "ContinuumStoreTests", dependencies: ["ContinuumCore", "ContinuumStore"]),
        .testTarget(name: "ContinuumSystemTests", dependencies: ["ContinuumCore", "ContinuumSystem"]),
        .testTarget(name: "ContinuumRuntimeTests", dependencies: ["ContinuumRuntime"]),
        .testTarget(name: "ContinuumAppTests", dependencies: ["ContinuumApp", "ContinuumSystem"])
    ]
)
