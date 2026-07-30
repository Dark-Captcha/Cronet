// The C ABI declared in cronet.h, translating between plain C values and the
// C++ objects that do the work.

#include "cronet.h"

#include <algorithm>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include "base/containers/span.h"
#include "base/memory/scoped_refptr.h"
#include "call.h"
#include "components/cronet/version.h"
#include "engine.h"

// The handle a caller holds. An engine is passed back as itself, but a call
// has to keep a reference, so it gets a struct of its own.
struct cronet_call {
  scoped_refptr<cronet_standalone::CallState> state;
};

namespace {

cronet_standalone::Engine* Unwrap(cronet_engine* engine) {
  return reinterpret_cast<cronet_standalone::Engine*>(engine);
}

std::string ToString(const char* value) {
  return value ? std::string(value) : std::string();
}

// Per thread so that concurrent callers never overwrite each other's reason.
// A fixed array rather than a std::string because a thread-local with a
// destructor would run at thread exit for every thread that ever touches the
// library, whether or not it saw an error.
constexpr size_t kLastErrorSize = 512;
thread_local char g_last_error[kLastErrorSize] = {};

void SetLastError(std::string_view message) {
  base::span<char> destination(g_last_error);
  const size_t length = std::min(message.size(), destination.size() - 1);
  destination.first(length).copy_from(base::span(message).first(length));
  destination[length] = '\0';
}

net::RequestPriority ToRequestPriority(int32_t priority) {
  if (priority < net::MINIMUM_PRIORITY || priority > net::MAXIMUM_PRIORITY) {
    return net::MEDIUM;
  }
  return static_cast<net::RequestPriority>(priority);
}

}  // namespace

extern "C" {

int32_t cronet_abi_version(void) {
  return CRONET_ABI_VERSION;
}

const char* cronet_version(void) {
  return CRONET_VERSION;
}

void cronet_engine_config_init(cronet_engine_config* config) {
  if (!config) {
    return;
  }
  *config = cronet_engine_config{};
  config->enable_quic = 1;
  config->enable_http2 = 1;
  config->enable_brotli = 1;
  config->cache_mode = CRONET_CACHE_DISABLED;
}

const char* cronet_last_error(void) {
  return g_last_error;
}

cronet_engine* cronet_engine_create(const cronet_engine_config* config) {
  if (!config) {
    SetLastError("config must not be null");
    return nullptr;
  }

  cronet_standalone::EngineConfig engine_config;
  engine_config.user_agent = ToString(config->user_agent);
  engine_config.accept_language = ToString(config->accept_language);
  engine_config.experimental_options = ToString(config->experimental_options);
  engine_config.storage_path = ToString(config->storage_path);
  engine_config.proxy_rules = ToString(config->proxy_rules);
  engine_config.proxy_bypass_rules = ToString(config->proxy_bypass_rules);
  engine_config.proxy_username = ToString(config->proxy_username);
  engine_config.proxy_password = ToString(config->proxy_password);
  engine_config.enable_quic = config->enable_quic != 0;
  engine_config.enable_http2 = config->enable_http2 != 0;
  engine_config.enable_brotli = config->enable_brotli != 0;
  engine_config.cache_mode = config->cache_mode;
  engine_config.cache_max_bytes = config->cache_max_bytes;
  // std::span rather than base::span: Chromium annotates base::span's
  // pointer-and-count constructor as unsafe buffer usage, and a C ABI has
  // nothing else to offer.
  for (const cronet_quic_hint& hint :
       std::span(config->quic_hints, config->quic_hint_count)) {
    if (!hint.host) {
      continue;
    }
    engine_config.quic_hints.push_back(
        {.host = hint.host,
         .port = hint.port > 0 ? hint.port : 443,
         .alternate_port = hint.alternate_port > 0 ? hint.alternate_port : 443});
  }

  std::string failure;
  cronet_standalone::Engine* engine =
      cronet_standalone::Engine::Create(engine_config, &failure);
  if (!engine) {
    SetLastError(failure);
    return nullptr;
  }
  return reinterpret_cast<cronet_engine*>(engine);
}

void cronet_engine_destroy(cronet_engine* engine) {
  if (engine) {
    Unwrap(engine)->Destroy();
  }
}

int32_t cronet_engine_start_net_log(cronet_engine* engine,
                                    const char* path,
                                    int32_t log_all) {
  if (!engine || !path) {
    return 0;
  }
  return Unwrap(engine)->StartNetLog(path, log_all != 0) ? 1 : 0;
}

void cronet_engine_stop_net_log(cronet_engine* engine) {
  if (engine) {
    Unwrap(engine)->StopNetLog();
  }
}

void cronet_request_init(cronet_request* request) {
  if (!request) {
    return;
  }
  *request = cronet_request{};
  request->priority = CRONET_PRIORITY_MEDIUM;
  request->max_redirects = -1;
}

cronet_call* cronet_call_start(cronet_engine* engine,
                               const cronet_request* request) {
  if (!engine || !request || !request->url) {
    return nullptr;
  }

  cronet_standalone::RequestSpec spec;
  spec.url = request->url;
  spec.method = request->method && *request->method ? request->method : "GET";
  spec.priority = ToRequestPriority(request->priority);
  spec.max_redirects = request->max_redirects;
  spec.disable_cache = request->disable_cache != 0;
  spec.headers.reserve(request->header_count);
  for (const cronet_header& header :
       std::span(request->headers, request->header_count)) {
    if (!header.name || !header.value) {
      continue;
    }
    spec.headers.emplace_back(header.name, header.value);
  }
  if (request->body && request->body_size > 0) {
    spec.body.assign(reinterpret_cast<const char*>(request->body),
                     request->body_size);
  }

  scoped_refptr<cronet_standalone::CallState> state =
      cronet_standalone::StartCall(Unwrap(engine), spec);
  if (!state) {
    return nullptr;
  }
  return new cronet_call{std::move(state)};
}

int32_t cronet_call_state_of(const cronet_call* call) {
  return call ? call->state->state() : CRONET_CALL_STARTED;
}

int cronet_call_fd(const cronet_call* call) {
  return call ? call->state->completion_fd() : -1;
}

int64_t cronet_call_read(cronet_call* call, uint8_t* buffer, size_t capacity) {
  // A call that does not exist has no body left to hand over, which is the
  // same thing the end of one reports.
  if (!call || !buffer) {
    return CRONET_EOF;
  }
  return call->state->Read(buffer, capacity);
}

int32_t cronet_call_wait(cronet_call* call, int32_t timeout_ms) {
  return call && call->state->Wait(timeout_ms) ? 1 : 0;
}

const cronet_response* cronet_call_response(cronet_call* call) {
  return call ? call->state->response() : nullptr;
}

void cronet_call_cancel(cronet_call* call) {
  if (call) {
    call->state->Cancel();
  }
}

void cronet_call_free(cronet_call* call) {
  if (!call) {
    return;
  }
  // Stop the request and wait for the network thread to let go of it, so that
  // no callback can be in flight once the state is dropped.
  call->state->Cancel();
  call->state->WaitForRelease();
  delete call;
}

}  // extern "C"
