// swift-tools-version: 6.0
import PackageDescription

// The Rust core for the Mac app (LD-156 (2)). scripts/build-core.sh makes both
// parts in target/larsal-core/ and links Generated/ to it; neither is kept.
let package = Package(
    name: "LarsalCore",
    platforms: [.macOS(.v14)],
    products: [.library(name: "LarsalCore", targets: ["LarsalCore"])],
    targets: [
        // larsal-ffi as a static library, with its C header.
        .binaryTarget(name: "LarsalFFI", path: "Generated/LarsalFFI.xcframework"),
        // The Swift bindings UniFFI writes, built in Swift 5 mode as the
        // studied apps build theirs, and optimized in every build: the
        // generated code that lifts list rows is too slow unoptimized for
        // FEA-01.34's 50 ms on 10,000 entries (as the Rust crates, LD-161).
        .target(
            name: "LarsalCore",
            dependencies: ["LarsalFFI"],
            path: "Generated/Swift",
            swiftSettings: [.swiftLanguageMode(.v5), .unsafeFlags(["-O"])]
        ),
    ]
)
