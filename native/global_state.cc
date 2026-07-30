// The process-wide hooks Cronet's core leaves to whoever embeds it.
//
// The `cronet` namespace at the bottom defines what
// components/cronet/cronet_global_state.h declares. In Chrome the embedder is
// the browser process, which has already brought up a task runner, a command
// line and a proxy service long before //net asks for any of them. Here there
// is no browser, so this is where the library starts what //base and //net
// assume is already running.
//
// The `cronet_standalone` namespace at the top is the awkward consequence of
// one of those hooks: CreateProxyConfigService() is asked which proxy to use
// without being told which engine is asking. ScopedPendingProxyConfig is how an
// engine answers for itself; see global_state.h for why a lock is part of it.

#include "global_state.h"

#include <tuple>
#include <utility>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/feature_list.h"
#include "base/no_destructor.h"
#include "base/synchronization/lock.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/task/thread_pool.h"
#include "base/task/thread_pool/thread_pool_instance.h"
#include "components/cronet/cronet_global_state.h"
#include "net/proxy_resolution/configured_proxy_resolution_service.h"
#include "net/proxy_resolution/proxy_config_service.h"
#include "net/proxy_resolution/proxy_config_service_fixed.h"
#include "net/proxy_resolution/proxy_config_with_annotation.h"
#include "net/traffic_annotation/network_traffic_annotation.h"

namespace cronet_standalone {
namespace {

// Guards PendingProxyConfig() for the whole of an engine's construction,
// which is the window in which Cronet reads it.
base::Lock& PendingProxyConfigLock() {
  static base::NoDestructor<base::Lock> lock;
  return *lock;
}

std::optional<net::ProxyConfig>& PendingProxyConfig() {
  static base::NoDestructor<std::optional<net::ProxyConfig>> config;
  return *config;
}

constexpr net::NetworkTrafficAnnotationTag kProxyTrafficAnnotation =
    net::DefineNetworkTrafficAnnotation("cronet_standalone_proxy", R"(
      semantics {
        sender: "Cronet standalone library"
        description:
          "Proxy settings supplied by the application that embeds this "
          "library, applied to the requests it makes."
        trigger: "The embedder configured a proxy when creating an engine."
        data: "No data beyond the request itself."
        destination: OTHER
      }
      policy {
        cookies_allowed: NO
        setting: "Configured per engine by the embedding application."
        policy_exception_justification: "Not used in a Chrome browser."
      })");

}  // namespace

ScopedPendingProxyConfig::ScopedPendingProxyConfig(
    std::optional<net::ProxyConfig> config) {
  PendingProxyConfigLock().Acquire();
  PendingProxyConfig() = std::move(config);
}

ScopedPendingProxyConfig::~ScopedPendingProxyConfig() {
  PendingProxyConfig().reset();
  PendingProxyConfigLock().Release();
}

}  // namespace cronet_standalone

namespace cronet {

namespace {

scoped_refptr<base::SingleThreadTaskRunner> InitializeAndCreateTaskRunner() {
  // Nothing else in the process owns these, so the library brings them up: an
  // AtExitManager for //base's singletons, an empty command line, an empty
  // FeatureList so that feature checks resolve to their defaults, and a thread
  // pool.
  //
  // The command line is not optional: parts of //net read switches off it
  // while building a context — net::TrustStoreChrome does, when it applies the
  // Chrome root store's constraint overrides — and reading from a command line
  // that was never initialized dereferences null. An embedder that has already
  // initialized one keeps it.
  std::ignore = new base::AtExitManager;
  if (!base::CommandLine::InitializedForCurrentProcess()) {
    base::CommandLine::Init(0, nullptr);
  }
  base::FeatureList::InitInstance(std::string(), std::string());
  base::ThreadPoolInstance::CreateAndStartWithDefaultParams("cronet");
  return base::ThreadPool::CreateSingleThreadTaskRunner({});
}

base::SingleThreadTaskRunner* InitTaskRunner() {
  static base::NoDestructor<scoped_refptr<base::SingleThreadTaskRunner>> runner(
      InitializeAndCreateTaskRunner());
  return runner->get();
}

}  // namespace

void EnsureInitialized() {
  std::ignore = InitTaskRunner();
}

bool OnInitThread() {
  return InitTaskRunner()->BelongsToCurrentThread();
}

void PostTaskToInitThread(const base::Location& posted_from,
                          base::OnceClosure task) {
  InitTaskRunner()->PostTask(posted_from, std::move(task));
}

std::unique_ptr<net::ProxyConfigService> CreateProxyConfigService(
    const scoped_refptr<base::SequencedTaskRunner>& io_task_runner) {
  const std::optional<net::ProxyConfig>& pending =
      cronet_standalone::PendingProxyConfig();
  if (pending.has_value()) {
    return std::make_unique<net::ProxyConfigServiceFixed>(
        net::ProxyConfigWithAnnotation(
            *pending, cronet_standalone::kProxyTrafficAnnotation));
  }
  return net::ProxyConfigService::CreateSystemProxyConfigService(
      io_task_runner);
}

std::unique_ptr<net::ProxyResolutionService> CreateProxyResolutionService(
    std::unique_ptr<net::ProxyConfigService> proxy_config_service,
    net::NetLog* net_log) {
  return net::ConfiguredProxyResolutionService::CreateUsingSystemProxyResolver(
      std::move(proxy_config_service),
      /*host_resolver_for_override_rules=*/nullptr, net_log,
      /*quick_check_enabled=*/true);
}

std::string CreateDefaultUserAgent(const std::string& partial_user_agent) {
  return partial_user_agent;
}

void SetNetworkThreadPriorityOnNetworkThread(double priority) {
  // Left to the operating system: a library has no business renicing a thread
  // in a process it does not own.
}

}  // namespace cronet
