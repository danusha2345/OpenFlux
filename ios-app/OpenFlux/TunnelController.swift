import Foundation
import Combine

enum TransportKind: String, CaseIterable, Identifiable {
    case yandex = "yandex"
    case vyandex = "vyandex"
    case max = "oneme"
    case cupsonline = "cupsonline"
    case mailru = "mailru"
    var id: String { rawValue }
    var title: String {
        switch self {
        case .yandex: return "Yandex Docs"
        case .vyandex: return "Yandex Volga"
        case .max: return "MAX"
        case .cupsonline: return "Cups.online"
        case .mailru: return "Mail.ru Docs"
        }
    }
}

/// Swift wrapper around the OpenFlux Go static library (liboflux.a).
@MainActor
final class TunnelController: ObservableObject {
    @Published var running = false
    @Published var connected = false
    @Published var log: String = ""
    @Published var stats: String = ""

    private var timer: Timer?

    /// Local SOCKS5 listen address for the currently running session.
    private(set) var socksAddr = ""

    @Published var busy = false

    /// Starts the client tunnel over the selected transport.
    /// - port: local SOCKS5 port to listen on (127.0.0.1:port).
    /// The Go start call blocks until the transport is up (document auth can
    /// take many seconds), so it runs off the main actor to keep the UI alive.
    func start(transport: TransportKind, url: String, maxToken: String, maxUid: String,
               peerKey: String, port: Int) {
        guard !running, !busy else { return }
        busy = true
        let addr = "127.0.0.1:\(port)"
        socksAddr = addr
        let tt = transport.rawValue
        Task.detached {
            OpenFluxSetAllowPlaintext(0)
            peerKey.withCString { key in
                OpenFluxSetPeerKey(UnsafeMutablePointer(mutating: key))
            }
            let rc = tt.withCString { t in
                url.withCString { u in
                    addr.withCString { a in
                        maxToken.withCString { tok in
                            maxUid.withCString { uid in
                                OpenFluxStartClient(
                                    UnsafeMutablePointer(mutating: t),
                                    UnsafeMutablePointer(mutating: u),
                                    UnsafeMutablePointer(mutating: a),
                                    UnsafeMutablePointer(mutating: tok),
                                    UnsafeMutablePointer(mutating: uid)
                                )
                            }
                        }
                    }
                }
            }
            await MainActor.run {
                self.appendLog(Self.describe(rc: rc, addr: addr, port: port, transport: transport))
                self.busy = false
                self.running = OpenFluxIsRunning() != 0
                if self.running { self.startPolling() } else { self.pollOnce() }
            }
        }
    }

    private static func describe(rc: Int32, addr: String, port: Int, transport: TransportKind) -> String {
        switch rc {
        case 0: return "[app] started on \(addr) via \(transport.title)"
        case 1: return "[app] already running"
        case 2: return "[app] unknown transport"
        case 3: return "[app] transport failed to start (check URL / network)"
        case 4: return "[app] port \(port) is busy — pick another port"
        case 5: return "[app] internal error (see log)"
        case 6: return "[app] tunnel init failed"
        case 7: return "[app] bad exit public key — copy it from the exit node banner"
        default: return "[app] start failed (code \(rc))"
        }
    }

    func stop() {
        guard !busy else { return }
        busy = true
        timer?.invalidate()
        timer = nil
        Task.detached {
            OpenFluxStop()
            await MainActor.run {
                self.busy = false
                self.running = false
                self.connected = false
                self.pollOnce()
            }
        }
    }

    private func startPolling() {
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.pollOnce() }
        }
    }

    private func pollOnce() {
        running = OpenFluxIsRunning() != 0
        connected = OpenFluxIsConnected() != 0

        if let c = OpenFluxReadLog() {
            let s = String(cString: c)
            OpenFluxFreeString(c)
            if !s.isEmpty { appendLog(s) }
        }
        if let c = OpenFluxStatsJSON() {
            stats = String(cString: c)
            OpenFluxFreeString(c)
        }
    }

    private func appendLog(_ s: String) {
        log += (log.isEmpty ? "" : "\n") + s
        if log.count > 20000 {
            log = String(log.suffix(20000))
        }
    }

    /// Connectivity check routed through the local SOCKS5 proxy.
    func testThroughProxy() {
        guard !socksAddr.isEmpty else { return }
        appendLog("[app] test request via SOCKS5 \(socksAddr) ...")
        let config = URLSessionConfiguration.ephemeral
        let parts = socksAddr.split(separator: ":")
        let host = String(parts.first ?? "127.0.0.1")
        let port = Int(parts.last ?? "1080") ?? 1080
        config.connectionProxyDictionary = [
            "SOCKSEnable": 1,
            "SOCKSProxy": host,
            "SOCKSPort": port
        ]
        config.timeoutIntervalForRequest = 20
        let session = URLSession(configuration: config)
        let url = URL(string: "http://ifconfig.me/ip")!
        let task = session.dataTask(with: url) { [weak self] data, _, err in
            Task { @MainActor in
                if let err = err {
                    self?.appendLog("[app] test failed: \(err.localizedDescription)")
                } else if let data = data, let body = String(data: data, encoding: .utf8) {
                    self?.appendLog("[app] test OK, exit IP: \(body.trimmingCharacters(in: .whitespacesAndNewlines))")
                } else {
                    self?.appendLog("[app] test returned no data")
                }
            }
        }
        task.resume()
    }
}
