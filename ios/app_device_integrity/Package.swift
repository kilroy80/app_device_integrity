// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "app_device_integrity",
    platforms: [
        .iOS("13.0"),
        .macOS("10.15")
    ],
    products: [
        .library(name: "app-device-integrity", targets: ["app_device_integrity"])
    ],
    dependencies: [
        .package(name: "FlutterFramework", path: "../FlutterFramework")
    ],
    targets: [
        .target(
            name: "app_device_integrity",
            dependencies: [
                .product(name: "FlutterFramework", package: "FlutterFramework")
            ],
            resources: [
                // .process("PrivacyInfo.xcprivacy"),
            ]
        )
    ]
)