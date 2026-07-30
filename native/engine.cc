// The engine declared in engine.h: building a Chromium network context out of a
// flat configuration, and taking it back down again.
//
// Most of the length here is the CronetContext::Callback surface, which an
// embedder must implement whole even when, as here, it has nothing to report.

#include "engine.h"

#include <memory>
#include <utility>
#include <vector>

#include "base/functional/bind.h"
#include "base/location.h"
#include "base/memory/ptr_util.h"
#include "base/strings/utf_string_conversions.h"
#include "call.h"
#include "components/cronet/cronet_global_state.h"
#include "components/cronet/url_request_context_config.h"
#include "global_state.h"
#include "net/base/auth.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/proxy_chain.h"
#include "net/base/proxy_server.h"
#include "net/http/http_auth.h"
#include "net/http/http_auth_cache.h"
#include "net/http/http_network_session.h"
#include "net/http/http_transaction_factory.h"
#include "net/proxy_resolution/proxy_list.h"
#include "net/url_request/url_request_context.h"
#include "url/scheme_host_port.h"

namespace cronet_standalone {
namespace {

// A proxy that asks for Basic credentials is answered from the auth cache
// without the extra 407 round trip. The realm is left empty because it is not
// known before the challenge arrives, and nothing reads it: Chromium answers
// preemptively through HttpAuthCache::LookupByPath, which matches on the path
// and never compares the realm.
void PreloadProxyCredentialsOnNetworkThread(
    cronet::CronetContext* context,
    std::vector<url::SchemeHostPort> proxies,
    std::u16string username,
    std::u16string password) {
  net::HttpAuthCache* auth_cache = context->GetURLRequestContext()
                                       ->http_transaction_factory()
                                       ->GetSession()
                                       ->http_auth_cache();
  for (const url::SchemeHostPort& proxy : proxies) {
    auth_cache->Add(proxy, net::HttpAuth::AUTH_PROXY, /*realm=*/std::string(),
                    net::HttpAuth::AUTH_SCHEME_BASIC,
                    net::NetworkAnonymizationKey(), "Basic realm=\"\"",
                    net::AuthCredentials(username, password), /*path=*/"/");
  }
}

void CollectHttpProxies(const net::ProxyList& list,
                        std::vector<url::SchemeHostPort>* out) {
  for (const net::ProxyChain& chain : list.AllChains()) {
    if (chain.is_direct() || !chain.is_single_proxy()) {
      continue;
    }
    const net::ProxyServer& server = chain.First();
    // Only http and https proxies speak HTTP authentication at all; SOCKS
    // carries its credentials inside its own handshake.
    if (!server.is_http() && !server.is_https()) {
      continue;
    }
    out->emplace_back(server.is_https() ? "https" : "http",
                      server.host_port_pair().host(),
                      server.host_port_pair().port());
  }
}

}  // namespace

Engine::Engine() = default;

Engine::~Engine() = default;

Engine* Engine::Create(const EngineConfig& config, std::string* error) {
  cronet::EnsureInitialized();

  cronet::URLRequestContextConfigBuilder builder;
  builder.enable_quic = config.enable_quic;
  builder.enable_spdy = config.enable_http2;
  builder.enable_brotli = config.enable_brotli;
  builder.user_agent = config.user_agent;
  builder.accept_language = config.accept_language;
  builder.storage_path = config.storage_path;
  if (!config.experimental_options.empty()) {
    builder.experimental_options = config.experimental_options;
  }

  switch (config.cache_mode) {
    case 0:
      builder.http_cache = cronet::URLRequestContextConfig::DISABLED;
      break;
    case 1:
      builder.http_cache = cronet::URLRequestContextConfig::MEMORY;
      break;
    case 2:
      builder.http_cache = cronet::URLRequestContextConfig::DISK;
      if (config.storage_path.empty()) {
        *error = "an on-disk cache needs a storage_path";
        return nullptr;
      }
      break;
    default:
      *error = "cache_mode must be 0 (off), 1 (in memory) or 2 (on disk)";
      return nullptr;
  }
  builder.http_cache_max_size = static_cast<int>(config.cache_max_bytes);

  std::unique_ptr<cronet::URLRequestContextConfig> context_config =
      builder.Build();
  if (!context_config) {
    *error = "experimental_options is not a JSON object Cronet accepts";
    return nullptr;
  }

  for (const QuicHint& hint : config.quic_hints) {
    context_config->quic_hints.push_back(
        std::make_unique<cronet::URLRequestContextConfig::QuicHint>(
            hint.host, hint.port, hint.alternate_port));
  }

  std::optional<net::ProxyConfig> proxy_config;
  if (!config.proxy_rules.empty()) {
    net::ProxyConfig parsed;
    parsed.proxy_rules().ParseFromString(config.proxy_rules);
    if (parsed.proxy_rules().empty()) {
      *error = "proxy_rules could not be parsed: " + config.proxy_rules;
      return nullptr;
    }
    if (!config.proxy_bypass_rules.empty()) {
      parsed.proxy_rules().bypass_rules.ParseFromString(
          config.proxy_bypass_rules);
    }
    proxy_config = std::move(parsed);
  }

  Engine* engine = new Engine();
  base::WaitableEvent initialized;
  {
    // Cronet reads the pending proxy configuration while building the context,
    // so it has to stay installed across both statements below.
    ScopedPendingProxyConfig pending(proxy_config);
    // Handed over as the base class: the context owns the callback and deletes
    // it through the virtual destructor, so Engine's own stays private.
    engine->context_ = new cronet::CronetContext(
        std::move(context_config),
        base::WrapUnique<cronet::CronetContext::Callback>(engine));
    cronet::PostTaskToInitThread(
        FROM_HERE,
        base::BindOnce(
            [](cronet::CronetContext* context, base::WaitableEvent* done) {
              context->InitRequestContextOnInitThread();
              done->Signal();
            },
            engine->context_.get(), &initialized));
    initialized.Wait();
  }

  if (proxy_config.has_value() && !config.proxy_username.empty()) {
    engine->PreloadProxyCredentials(proxy_config->proxy_rules(),
                                    config.proxy_username,
                                    config.proxy_password);
  }
  return engine;
}

void Engine::Destroy() {
  {
    base::AutoLock auto_lock(lock_);
    is_shutting_down_ = true;
    for (CallState* call : live_calls_) {
      call->Cancel();
    }
    while (!live_calls_.empty()) {
      all_calls_finished_.Wait();
    }
  }
  // Destroying the context destroys the callback it owns, which is `this`.
  delete context_.get();
}

bool Engine::RegisterCall(CallState* call) {
  base::AutoLock auto_lock(lock_);
  if (is_shutting_down_) {
    return false;
  }
  live_calls_.insert(call);
  return true;
}

void Engine::UnregisterCall(CallState* call) {
  base::AutoLock auto_lock(lock_);
  live_calls_.erase(call);
  if (live_calls_.empty()) {
    all_calls_finished_.Broadcast();
  }
}

bool Engine::StartNetLog(const std::string& path, bool log_all) {
  base::AutoLock auto_lock(lock_);
  if (is_net_logging_ || !context_->StartNetLogToFile(path, log_all)) {
    return false;
  }
  is_net_logging_ = true;
  return true;
}

void Engine::StopNetLog() {
  {
    base::AutoLock auto_lock(lock_);
    // Cronet answers a stop with no log running by returning early and never
    // calling OnStopNetLogCompleted, so waiting on it would wait forever.
    if (!is_net_logging_) {
      return;
    }
    is_net_logging_ = false;
    net_log_stopped_.Reset();
  }
  context_->StopNetLog();
  net_log_stopped_.Wait();
}

void Engine::PreloadProxyCredentials(const net::ProxyConfig::ProxyRules& rules,
                                     const std::string& username,
                                     const std::string& password) {
  std::vector<url::SchemeHostPort> proxies;
  CollectHttpProxies(rules.single_proxies, &proxies);
  CollectHttpProxies(rules.proxies_for_http, &proxies);
  CollectHttpProxies(rules.proxies_for_https, &proxies);
  CollectHttpProxies(rules.fallback_proxies, &proxies);
  if (proxies.empty()) {
    return;
  }

  context_->PostTaskToNetworkThread(
      FROM_HERE,
      base::BindOnce(&PreloadProxyCredentialsOnNetworkThread,
                     base::Unretained(context_.get()), std::move(proxies),
                     base::UTF8ToUTF16(username), base::UTF8ToUTF16(password)));
}

void Engine::OnInitNetworkThread() {}

void Engine::OnDestroyNetworkThread() {
  context_ = nullptr;
}

void Engine::OnEffectiveConnectionTypeChanged(
    net::EffectiveConnectionType effective_connection_type) {}

void Engine::OnRTTOrThroughputEstimatesComputed(
    int32_t http_rtt_ms,
    int32_t transport_rtt_ms,
    int32_t downstream_throughput_kbps) {}

void Engine::OnRTTObservation(int32_t rtt_ms,
                              int32_t timestamp_ms,
                              net::NetworkQualityObservationSource source) {}

void Engine::OnThroughputObservation(
    int32_t throughput_kbps,
    int32_t timestamp_ms,
    net::NetworkQualityObservationSource source) {}

void Engine::OnStopNetLogCompleted() {
  net_log_stopped_.Signal();
}

void Engine::OnBeforeTunnelRequest(
    int chain_id,
    net::ProxyDelegate::OnBeforeTunnelRequestCallback callback) {
  // Add no headers of our own. The answer has to be posted, not run inline:
  // CronetProxyDelegate has already returned ERR_IO_PENDING to //net on this
  // stack, so //net is not yet ready to be completed.
  context_->PostTaskToNetworkThread(
      FROM_HERE,
      base::BindOnce(
          [](net::ProxyDelegate::OnBeforeTunnelRequestCallback callback) {
            std::move(callback).Run(net::HttpRequestHeaders());
          },
          std::move(callback)));
}

void Engine::OnTunnelHeadersReceived(
    int chain_id,
    const net::HttpResponseHeaders& response_headers,
    net::CompletionOnceCallback callback) {
  context_->PostTaskToNetworkThread(
      FROM_HERE, base::BindOnce(
                     [](net::CompletionOnceCallback callback) {
                       std::move(callback).Run(net::OK);
                     },
                     std::move(callback)));
}

}  // namespace cronet_standalone
