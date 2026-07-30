// The engine: one Chromium network context, the flat configuration it is built
// from, and the bookkeeping that makes tearing it down safe while calls are
// still running.
//
// Configuration crosses this boundary as plain values rather than as Chromium
// types, so the C ABI in cronet.h has something it can describe.

#ifndef CRONET_STANDALONE_ENGINE_H_
#define CRONET_STANDALONE_ENGINE_H_

#include <stdint.h>

#include <optional>
#include <string>
#include <vector>

#include "base/containers/flat_set.h"
#include "base/memory/raw_ptr.h"
#include "base/synchronization/condition_variable.h"
#include "base/synchronization/lock.h"
#include "base/synchronization/waitable_event.h"
#include "components/cronet/cronet_context.h"
#include "net/proxy_resolution/proxy_config.h"

namespace cronet_standalone {

class CallState;

// A host already known to speak HTTP/3, so the first request to it can skip
// the round trip that would otherwise discover that.
struct QuicHint {
  std::string host;
  int port = 443;
  int alternate_port = 443;
};

struct EngineConfig {
  std::string user_agent;
  std::string accept_language;
  std::string experimental_options;
  std::string storage_path;
  std::string proxy_rules;
  std::string proxy_bypass_rules;
  std::string proxy_username;
  std::string proxy_password;
  bool enable_quic = true;
  bool enable_http2 = true;
  bool enable_brotli = true;
  int cache_mode = 0;
  int64_t cache_max_bytes = 0;
  std::vector<QuicHint> quic_hints;
};

// One network thread, one set of connection pools, one DNS and TLS session
// cache. Calls made on an engine share all of them, which is what makes a
// second call to the same host cheap.
//
// Every method is safe to call from any thread.
class Engine final : public cronet::CronetContext::Callback {
 public:
  // Returns null and fills `error` when the configuration cannot be applied.
  // Blocks until the engine's context is ready to take requests.
  static Engine* Create(const EngineConfig& config, std::string* error);

  Engine(const Engine&) = delete;
  Engine& operator=(const Engine&) = delete;

  // Cancels every call still running, waits for the network thread to let go
  // of them, then tears down the context — which deletes `this`. Calls that
  // were cancelled stay valid; their owners must still free them.
  void Destroy();

  cronet::CronetContext* context() const { return context_; }

  // A call registers for as long as it holds a live request, so that Destroy()
  // knows what to wait for. Registration fails once Destroy() has begun, which
  // is how a call started during shutdown is refused rather than lost.
  bool RegisterCall(CallState* call);
  void UnregisterCall(CallState* call);

  bool StartNetLog(const std::string& path, bool log_all);
  void StopNetLog();

 private:
  Engine();
  ~Engine() override;

  // Offers `username`/`password` for every http/https proxy in `rules`, so
  // that a proxy asking for Basic auth is answered without a 407 round trip.
  void PreloadProxyCredentials(const net::ProxyConfig::ProxyRules& rules,
                               const std::string& username,
                               const std::string& password);

  // cronet::CronetContext::Callback. This library exposes no network quality
  // estimates and installs no proxy delegate, so most of these have nothing to
  // report; the two tunnel hooks answer "carry on" to keep a proxy tunnel from
  // stalling should one ever be installed.
  void OnInitNetworkThread() override;
  void OnDestroyNetworkThread() override;
  void OnEffectiveConnectionTypeChanged(
      net::EffectiveConnectionType effective_connection_type) override;
  void OnRTTOrThroughputEstimatesComputed(
      int32_t http_rtt_ms,
      int32_t transport_rtt_ms,
      int32_t downstream_throughput_kbps) override;
  void OnRTTObservation(int32_t rtt_ms,
                        int32_t timestamp_ms,
                        net::NetworkQualityObservationSource source) override;
  void OnThroughputObservation(
      int32_t throughput_kbps,
      int32_t timestamp_ms,
      net::NetworkQualityObservationSource source) override;
  void OnStopNetLogCompleted() override;
  void OnBeforeTunnelRequest(
      int chain_id,
      net::ProxyDelegate::OnBeforeTunnelRequestCallback callback) override;
  void OnTunnelHeadersReceived(int chain_id,
                               const net::HttpResponseHeaders& response_headers,
                               net::CompletionOnceCallback callback) override;

  // Owns `this`. Cleared on the network thread as the context goes away.
  raw_ptr<cronet::CronetContext> context_ = nullptr;

  base::Lock lock_;
  base::ConditionVariable all_calls_finished_{&lock_};
  base::flat_set<raw_ptr<CallState>> live_calls_ GUARDED_BY(lock_);
  bool is_shutting_down_ GUARDED_BY(lock_) = false;

  // StopNetLog() has to wait for the network thread to flush the file before
  // its caller may read it — but only when one is actually running, since
  // Cronet does not signal a stop it had nothing to stop.
  base::WaitableEvent net_log_stopped_;
  bool is_net_logging_ GUARDED_BY(lock_) = false;
};

}  // namespace cronet_standalone

#endif  // CRONET_STANDALONE_ENGINE_H_
