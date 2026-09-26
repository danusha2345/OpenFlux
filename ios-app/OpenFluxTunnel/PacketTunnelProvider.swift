import Foundation
import NetworkExtension

/// System VPN entry point. Bridges the device's IP packets to the OpenFlux Go
/// tun2socks stack (TCP forwarded through the transport; DNS proxied over TCP).
class PacketTunnelProvider: NEPacketTunnelProvider {
    private struct BypassRoute: Decodable {
        let destination: String
        let mask: String
    }

    private let loopStateLock = NSLock()
    private var stopped = false
    private var wasConnected = false
    private var connectionTimer: DispatchSourceTimer?

    private func isStopped() -> Bool {
        loopStateLock.lock()
        defer { loopStateLock.unlock() }
        return stopped
    }

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let conf = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration ?? [:]
        let transport = (conf["transport"] as? String) ?? "yandex"
        let connection: ConnectionSettings
        do {
            guard let saved = try SharedConnectionSettings.load() else {
                throw NSError(domain: "OpenFlux", code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Open OpenFlux to migrate connection settings"])
            }
            connection = saved
        } catch {
            completionHandler(error)
            return
        }

        loopStateLock.lock()
        stopped = false
        wasConnected = false
        loopStateLock.unlock()
        OpenFluxSetAllowPlaintext(0)
        connection.peerKey.withCString { key in
            OpenFluxSetPeerKey(UnsafeMutablePointer(mutating: key))
        }

        // Resolve physical carrier and DoT routes before installing the
        // default VPN route, or the extension can route into itself.
        let routeJSON = transport.withCString { tt in
            connection.url.withCString { u in
                OpenFluxResolveBypassRoutes(UnsafeMutablePointer(mutating: tt),
                                            UnsafeMutablePointer(mutating: u))
            }
        }
        guard let routeJSON = routeJSON else {
            completionHandler(NSError(domain: "OpenFlux", code: 8,
                userInfo: [NSLocalizedDescriptionKey: "Cannot resolve transport routes"])); return
        }
        let routeData = Data(String(cString: routeJSON).utf8)
        OpenFluxFreeString(routeJSON)
        let bypassRoutes: [BypassRoute]
        do { bypassRoutes = try JSONDecoder().decode([BypassRoute].self, from: routeData) }
        catch { completionHandler(error); return }
        if isStopped() {
            completionHandler(NSError(domain: "OpenFlux", code: 9,
                userInfo: [NSLocalizedDescriptionKey: "VPN start cancelled"])); return
        }

        // Virtual interface: capture all IPv4 + all DNS.
        let networkSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        // 10.10.10.2 is the address the exit node expects the client to use
        // (it hardcodes return packets to 10.10.10.2), enabling pure L3
        // forwarding with no gvisor stack in the extension.
        let ipv4 = NEIPv4Settings(addresses: ["10.10.10.2"], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        ipv4.excludedRoutes = bypassRoutes.map {
            NEIPv4Route(destinationAddress: $0.destination, subnetMask: $0.mask)
        }
        networkSettings.ipv4Settings = ipv4
        // Capture IPv6 as well. The Go packet bridge currently rejects it,
        // which forces applications to fall back to IPv4 instead of leaking
        // IPv6 outside the VPN.
        let ipv6 = NEIPv6Settings(addresses: ["fdfe:dcba:9876::1"], networkPrefixLengths: [126])
        ipv6.includedRoutes = [NEIPv6Route.default()]
        networkSettings.ipv6Settings = ipv6
        networkSettings.mtu = 1500
        // A benign in-tunnel DNS address: queries to it are captured and
        // answered locally over DoT (the real resolvers are excluded above).
        let dns = NEDNSSettings(servers: ["198.18.0.1"])
        dns.matchDomains = [""]
        networkSettings.dnsSettings = dns

        setTunnelNetworkSettings(networkSettings) { error in
            if let error = error {
                completionHandler(error)
                return
            }
            if self.isStopped() {
                completionHandler(NSError(domain: "OpenFlux", code: 9,
                    userInfo: [NSLocalizedDescriptionKey: "VPN start cancelled"])); return
            }
            let rc = transport.withCString { tt in
                connection.url.withCString { u in
                    connection.maxToken.withCString { tok in
                        connection.maxUid.withCString { uid in
                            OpenFluxStartPacketTunnel(
                                UnsafeMutablePointer(mutating: tt),
                                UnsafeMutablePointer(mutating: u),
                                UnsafeMutablePointer(mutating: tok),
                                UnsafeMutablePointer(mutating: uid))
                        }
                    }
                }
            }
            if rc != 0 {
                completionHandler(NSError(domain: "OpenFlux", code: Int(rc),
                    userInfo: [NSLocalizedDescriptionKey: "start failed (\(rc))"]))
                return
            }
            if self.isStopped() {
                OpenFluxStopPacketTunnel()
                completionHandler(NSError(domain: "OpenFlux", code: 9,
                    userInfo: [NSLocalizedDescriptionKey: "VPN start cancelled"])); return
            }
            self.startConnectionMonitor()
            self.startReadLoop()
            self.startWriteLoop()
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        loopStateLock.lock()
        stopped = true
        let timer = connectionTimer
        connectionTimer = nil
        wasConnected = false
        reasserting = false
        loopStateLock.unlock()
        timer?.cancel()
        OpenFluxStopPacketTunnel()
        completionHandler()
    }

    private func startConnectionMonitor() {
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.main)
        timer.schedule(deadline: .now(), repeating: .seconds(1))
        timer.setEventHandler { [weak self] in
            guard let self = self else { return }
            self.loopStateLock.lock()
            if !self.stopped {
                let connected = OpenFluxPacketTunnelIsConnected() != 0
                if connected { self.wasConnected = true }
                self.reasserting = self.wasConnected && !connected
            }
            self.loopStateLock.unlock()
        }
        loopStateLock.lock()
        connectionTimer = timer
        loopStateLock.unlock()
        timer.resume()
    }

    /// Device -> Go stack.
    private func startReadLoop() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self = self else { return }
            self.loopStateLock.lock()
            let stopped = self.stopped
            self.loopStateLock.unlock()
            if stopped { return }
            for p in packets {
                p.withUnsafeBytes { raw in
                    if let base = raw.bindMemory(to: CChar.self).baseAddress {
                        OpenFluxTunWritePacket(UnsafeMutablePointer(mutating: base), Int32(p.count))
                    }
                }
            }
            self.startReadLoop()
        }
    }

    /// Go stack -> device.
    private func startWriteLoop() {
        DispatchQueue.global(qos: .userInitiated).async {
            let maxLen: Int32 = 65535
            let buf = UnsafeMutablePointer<CChar>.allocate(capacity: Int(maxLen))
            defer { buf.deallocate() }
            while true {
                let n = OpenFluxTunReadPacket(buf, maxLen)
                if n < 0 { break }
                if n == 0 { continue }
                let data = Data(bytes: buf, count: Int(n))
                self.packetFlow.writePackets([data], withProtocols: [NSNumber(value: AF_INET)])
            }
        }
    }
}
