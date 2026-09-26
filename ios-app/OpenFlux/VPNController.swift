import Foundation
import NetworkExtension
import Combine

/// Controls only this application's packet-tunnel profile.
@MainActor
final class VPNController: ObservableObject {
    @Published var status: String = "Disconnected"
    @Published var active = false

    private var manager: NETunnelProviderManager?
    private var loaded = false
    private var loadGeneration = 0
    private var loadTask: Task<NETunnelProviderManager?, Error>?
    private var operation: Task<Void, Never>?
    private let extensionBundleId = "com.p1neapplexpress-saharev.openflux.tunnel"

    init() {
        NotificationCenter.default.addObserver(
            self, selector: #selector(statusChanged),
            name: .NEVPNStatusDidChange, object: nil)
        Task {
            do { try await load() }
            catch {
                if operation == nil { status = "Error: \(error.localizedDescription)" }
            }
        }
    }

    private func load() async throws {
        if loaded { return }
        if loadTask == nil {
            loadGeneration += 1
            let bundleId = extensionBundleId
            loadTask = Task {
                let managers = try await NETunnelProviderManager.loadAllFromPreferences()
                return managers.first {
                    ($0.protocolConfiguration as? NETunnelProviderProtocol)?
                        .providerBundleIdentifier == bundleId
                }
            }
        }
        guard let task = loadTask else { return }
        let generation = loadGeneration
        do {
            let existing = try await task.value
            // Several callers may await the same task. Only its first consumer
            // publishes the result; a later consumer must not erase a new profile.
            if !loaded { manager = existing; loaded = true }
            if generation == loadGeneration { loadTask = nil }
            refreshStatus()
        } catch {
            if generation == loadGeneration { loadTask = nil }
            throw error // A load failure must never create a duplicate profile.
        }
    }

    func start(transport: String, settings: ConnectionSettings) {
        guard operation == nil, !active else { return }
        do { try SharedConnectionSettings.save(settings) }
        catch { status = "Error: \(error.localizedDescription)"; return }
        active = true
        status = "Preparing…"
        operation = Task {
            defer {
                operation = nil
                if !status.hasPrefix("Error:") && !status.hasPrefix("Stop failed:") {
                    refreshStatus()
                }
            }
            do {
                try await load()
                try Task.checkCancellation()
                let m = manager ?? NETunnelProviderManager()
                manager = m
                let proto = NETunnelProviderProtocol()
                proto.providerBundleIdentifier = extensionBundleId
                proto.serverAddress = "OpenFlux"
                proto.providerConfiguration = ["transport": transport]
                m.protocolConfiguration = proto
                m.localizedDescription = "OpenFlux"
                m.isEnabled = true
                m.onDemandRules = [NEOnDemandRuleConnect()]
                m.isOnDemandEnabled = true
                try await m.saveToPreferences()
                try Task.checkCancellation()
                try await m.loadFromPreferences()
                try Task.checkCancellation()
                try m.connection.startVPNTunnel()
                status = "Connecting…"
            } catch {
                let cancelled = Task.isCancelled
                do { try await disableAndStop() }
                catch {
                    active = manager?.connection.status != .disconnected && manager != nil
                    status = "Stop failed: \(error.localizedDescription)"
                    return
                }
                active = false
                status = cancelled ? "Disconnected" : "Error: \(error.localizedDescription)"
            }
        }
    }

    /// Merge old app/profile values before removing their plaintext copies.
    func migrateLegacyConfiguration(_ current: ConnectionSettings) async throws -> ConnectionSettings {
        try await load()
        let stored = try SharedConnectionSettings.load()
        var settings = stored ?? current
        let proto = manager?.protocolConfiguration as? NETunnelProviderProtocol
        var conf = proto?.providerConfiguration ?? [:]
        let oldKeys = ["url", "maxToken", "maxUid", "peerKey"]
        if stored == nil {
            if settings.url.isEmpty { settings.url = conf["url"] as? String ?? "" }
            if settings.maxToken.isEmpty { settings.maxToken = conf["maxToken"] as? String ?? "" }
            if settings.maxUid.isEmpty { settings.maxUid = conf["maxUid"] as? String ?? "" }
            if settings.peerKey.isEmpty { settings.peerKey = conf["peerKey"] as? String ?? "" }
        }
        if stored == nil && (!settings.url.isEmpty || !settings.maxToken.isEmpty ||
                             !settings.maxUid.isEmpty || !settings.peerKey.isEmpty) {
            try SharedConnectionSettings.save(settings)
        }
        if let manager, let proto, oldKeys.contains(where: { conf[$0] != nil }) {
            let original = conf
            for key in oldKeys { conf.removeValue(forKey: key) }
            proto.providerConfiguration = conf
            manager.protocolConfiguration = proto
            do { try await manager.saveToPreferences() }
            catch {
                proto.providerConfiguration = original
                manager.protocolConfiguration = proto
                throw error
            }
        }
        SharedConnectionSettings.clearLegacyValues()
        return settings
    }

    func stop() {
        if let operation {
            operation.cancel()
            status = "Stopping…"
            return
        }
        guard manager != nil else { return }
        active = true
        status = "Stopping…"
        operation = Task {
            defer {
                operation = nil
                if !status.hasPrefix("Error:") && !status.hasPrefix("Stop failed:") {
                    refreshStatus()
                }
            }
            do {
                try await disableAndStop()
                active = false
                status = "Disconnected"
            } catch {
                status = "Stop failed: \(error.localizedDescription)"
            }
        }
    }

    private func disableAndStop() async throws {
        guard let manager else { return }
        manager.isOnDemandEnabled = false
        // Even a preferences error must not skip the immediate stop request.
        defer { manager.connection.stopVPNTunnel() }
        try await manager.saveToPreferences()
    }

    @objc private func statusChanged() { refreshStatus() }

    private func refreshStatus() {
        // Preferences/status notifications can arrive while start/stop awaits.
        // They must not re-enable the Start button during that operation.
        guard operation == nil else { return }
        guard let conn = manager?.connection else { active = false; status = "Disconnected"; return }
        switch conn.status {
        case .connected:     status = "Connected";     active = true
        case .connecting:    status = "Connecting…";   active = true
        case .disconnecting: status = "Disconnecting…"; active = true
        case .reasserting:   status = "Reasserting…";  active = true
        default:             status = "Disconnected";  active = false
        }
    }
}
