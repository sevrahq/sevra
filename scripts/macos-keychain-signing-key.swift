#!/usr/bin/env swift

import Foundation
import Security

private let service = "com.sevra.release-signing"
private let account = "SEVRA_CLI_SIGNING_KEY"

private enum SecretError: Error, CustomStringConvertible {
    case usage
    case emptySecret
    case keychain(OSStatus)
    case missing

    var description: String {
        switch self {
        case .usage:
            return "usage: macos-keychain-signing-key (put|get|has|delete)"
        case .emptySecret:
            return "refusing to store an empty signing key"
        case .keychain(let status):
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "unknown error"
            return "Keychain operation failed (\(status)): \(message)"
        case .missing:
            return "release signing key is missing from the local Keychain cache"
        }
    }
}

private func query() -> [String: Any] {
    [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
    ]
}

private func put(_ data: Data) throws {
    guard !data.isEmpty else { throw SecretError.emptySecret }
    let update: [String: Any] = [
        kSecValueData as String: data,
        kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    ]
    var status = SecItemUpdate(query() as CFDictionary, update as CFDictionary)
    if status == errSecItemNotFound {
        var item = query()
        update.forEach { item[$0.key] = $0.value }
        status = SecItemAdd(item as CFDictionary, nil)
    }
    guard status == errSecSuccess else { throw SecretError.keychain(status) }
}

private func get() throws -> Data {
    var request = query()
    request[kSecReturnData as String] = kCFBooleanTrue
    request[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    let status = SecItemCopyMatching(request as CFDictionary, &result)
    if status == errSecItemNotFound { throw SecretError.missing }
    guard status == errSecSuccess, let data = result as? Data else {
        throw SecretError.keychain(status)
    }
    return data
}

private func has() throws -> Bool {
    var request = query()
    request[kSecMatchLimit as String] = kSecMatchLimitOne
    let status = SecItemCopyMatching(request as CFDictionary, nil)
    if status == errSecItemNotFound { return false }
    guard status == errSecSuccess else { throw SecretError.keychain(status) }
    return true
}

private func delete() throws {
    let status = SecItemDelete(query() as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
        throw SecretError.keychain(status)
    }
}

do {
    guard CommandLine.arguments.count == 2 else { throw SecretError.usage }
    switch CommandLine.arguments[1] {
    case "put":
        try put(FileHandle.standardInput.readDataToEndOfFile())
    case "get":
        try FileHandle.standardOutput.write(contentsOf: get())
    case "has":
        exit(try has() ? EXIT_SUCCESS : 3)
    case "delete":
        try delete()
    default:
        throw SecretError.usage
    }
} catch {
    FileHandle.standardError.write(Data("release-keychain: \(error)\n".utf8))
    exit(EXIT_FAILURE)
}
