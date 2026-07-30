// The process-wide hooks Cronet's core reaches for, implemented for a plain
// library with no browser process around it.

#ifndef CRONET_STANDALONE_GLOBAL_STATE_H_
#define CRONET_STANDALONE_GLOBAL_STATE_H_

#include <optional>

#include "net/proxy_resolution/proxy_config.h"

namespace cronet_standalone {

// Cronet chooses a proxy configuration through one process-wide hook,
// cronet::CreateProxyConfigService(), which takes no engine to ask about. Hold
// this across an engine's construction and that hook answers with `config` for
// that engine alone: the constructor takes a process-wide lock which the
// destructor releases, so a second engine cannot be built in between and claim
// the value. An empty `config` restores the default, which is to read the
// system proxy settings.
class ScopedPendingProxyConfig {
 public:
  explicit ScopedPendingProxyConfig(std::optional<net::ProxyConfig> config);

  ScopedPendingProxyConfig(const ScopedPendingProxyConfig&) = delete;
  ScopedPendingProxyConfig& operator=(const ScopedPendingProxyConfig&) = delete;

  ~ScopedPendingProxyConfig();
};

}  // namespace cronet_standalone

#endif  // CRONET_STANDALONE_GLOBAL_STATE_H_
