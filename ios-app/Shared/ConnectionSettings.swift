import Foundation
import Security

// Both targets list the same Keychain access group first in their entitlements.
// The default group therefore lets the app and packet-tunnel extension read the
// same item without embedding credentials in VPN preferences.
struct ConnectionSettings: Codable {
    var url = ""
    var maxToken = ""
    var maxUid = ""
    var peerKey = ""
}

enum SharedConnectionSettings {
    private static let service = "com.p1neapplexpress-saharev.openflux"
    private static let account = "connection-settings"
    private static let legacyKeys = ["docURL", "maxToken", "maxUid", "peerKey"]

    private static var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }

    static func load() throws -> ConnectionSettings? {
        var request = query
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw keychainError(status)
        }
        return try JSONDecoder().decode(ConnectionSettings.self, from: data)
    }

    static func save(_ settings: ConnectionSettings) throws {
        let data = try JSONEncoder().encode(settings)
        let attributes: [String: Any] = [kSecValueData as String: data,
                                         kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecSuccess { return }
        guard status == errSecItemNotFound else { throw keychainError(status) }
        var item = query
        item.merge(attributes) { _, new in new }
        let addStatus = SecItemAdd(item as CFDictionary, nil)
        if addStatus != errSecSuccess { throw keychainError(addStatus) }
    }

    // The containing app reads both stores, then merges the old VPN profile
    // before writing Keychain. Keep UserDefaults until that entire step works.
    static func loadOrReadLegacy() throws -> ConnectionSettings {
        if let settings = try load() { return settings }
        let defaults = UserDefaults.standard
        return ConnectionSettings(
            url: defaults.string(forKey: "docURL") ?? "",
            maxToken: defaults.string(forKey: "maxToken") ?? "",
            maxUid: defaults.string(forKey: "maxUid") ?? "",
            peerKey: defaults.string(forKey: "peerKey") ?? "")
    }

    static func clearLegacyValues() {
        for key in legacyKeys { UserDefaults.standard.removeObject(forKey: key) }
    }

    private static func keychainError(_ status: OSStatus) -> NSError {
        NSError(domain: NSOSStatusErrorDomain, code: Int(status),
                userInfo: [NSLocalizedDescriptionKey: "Keychain error \(status)"])
    }
}
