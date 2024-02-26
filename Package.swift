// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftRSA",
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "SwiftRSA",
            targets: ["SwiftRSA"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        .package(url: "https://github.com/leif-ibsen/BigInt", from: "1.16.0"),
        .package(url: "https://github.com/leif-ibsen/ASN1", from: "2.4.0"),
        .package(url: "https://github.com/leif-ibsen/Digest", from: "1.3.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(name: "SwiftRSA", dependencies: ["BigInt", "ASN1", "Digest"]),
        .testTarget(name: "SwiftRSATests", dependencies: ["SwiftRSA"]),
    ]
)
