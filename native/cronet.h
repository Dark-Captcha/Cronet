// C ABI for a standalone build of Cronet, Chromium's network stack.
//
// Every function here is safe to call from any thread, and any number of calls
// may be in flight on one engine at once. The only thread-local state is the
// cronet_last_error() buffer; the library takes no process-wide locks on the
// request path, and never calls back into the caller: completion is signalled
// by making a file descriptor readable, so an event loop can wait on it
// without a callback thread.
//
// Ownership is deliberately flat. An engine outlives the calls made on it; a
// call owns its own response. Two functions free everything the library
// allocates: cronet_call_free() and cronet_engine_destroy().

#ifndef CRONET_H_
#define CRONET_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CRONET_EXPORT __attribute__((visibility("default")))

// Bumped whenever a struct in this header changes shape or a function changes
// meaning. A caller built against a different value is reading these structs at
// the wrong offsets, which corrupts silently rather than failing — so check it
// before the first call.
#define CRONET_ABI_VERSION 3

CRONET_EXPORT int32_t cronet_abi_version(void);

// The Chromium version this library was built from, e.g. "150.0.7871.100".
CRONET_EXPORT const char* cronet_version(void);

// A header name/value pair. Request headers are sent in the order given.
typedef struct {
  const char* name;
  const char* value;
} cronet_header;

// Tells the engine a host is known to speak HTTP/3, so the first request to it
// can go out over QUIC instead of spending a round trip on HTTP/2 discovering
// the Alt-Svc header that says so.
typedef struct {
  const char* host;
  int32_t port;            // The origin's port, usually 443.
  int32_t alternate_port;  // Where QUIC listens, usually the same.
} cronet_quic_hint;

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

typedef struct cronet_engine cronet_engine;

// Where a response body may be served from.
typedef enum {
  CRONET_CACHE_DISABLED = 0,
  CRONET_CACHE_IN_MEMORY = 1,
  CRONET_CACHE_ON_DISK = 2,
} cronet_cache_mode;

typedef struct {
  // Sent as User-Agent when a request does not set the header itself. Empty
  // means Chromium's own default.
  const char* user_agent;
  // Sent as Accept-Language when a request does not set the header itself.
  const char* accept_language;
  // Cronet experimental options, as a JSON object. Empty means "{}".
  const char* experimental_options;
  // Required by CRONET_CACHE_ON_DISK, ignored otherwise.
  const char* storage_path;

  // Chromium proxy rules: "socks5://127.0.0.1:1080", "http://user-visible:8080",
  // or per-scheme "http=http://a:8080;https=socks5://b:1080". Empty means the
  // system proxy settings. Schemes: http, https, socks4, socks5, direct.
  const char* proxy_rules;
  // Hosts that bypass the proxy, e.g. "localhost;*.internal;10.0.0.0/8".
  const char* proxy_bypass_rules;
  // Credentials for an http/https proxy, offered pre-emptively as Basic auth.
  // Chromium's SOCKS client does not authenticate, so these do not apply to a
  // socks4 or socks5 proxy.
  const char* proxy_username;
  const char* proxy_password;

  // Hosts already known to speak HTTP/3. Borrowed only for the duration of
  // cronet_engine_create.
  const cronet_quic_hint* quic_hints;
  size_t quic_hint_count;

  int32_t enable_quic;   // HTTP/3. Non-zero to allow.
  int32_t enable_http2;  // Non-zero to allow.
  int32_t enable_brotli;
  int32_t cache_mode;       // A cronet_cache_mode.
  int64_t cache_max_bytes;  // 0 lets Chromium choose.
} cronet_engine_config;

// Fills `config` with the library defaults. Call this before setting fields, so
// that a config stays valid as the struct grows.
CRONET_EXPORT void cronet_engine_config_init(cronet_engine_config* config);

// Creates an engine, or returns NULL and leaves the reason in
// cronet_last_error(). An engine owns one network thread and the connection
// pools, DNS cache and TLS session state shared by its calls.
CRONET_EXPORT cronet_engine* cronet_engine_create(
    const cronet_engine_config* config);

// Why the last call on *this thread* failed, or "" if none has. Owned by the
// library and valid until the next failing call on the same thread.
CRONET_EXPORT const char* cronet_last_error(void);

// Cancels every call still in flight, waits for them to finish unwinding, then
// tears the engine down. Safe to call with calls outstanding; those calls stay
// valid and must still be freed with cronet_call_free().
CRONET_EXPORT void cronet_engine_destroy(cronet_engine* engine);

// Writes a NetLog JSON trace to `path` until cronet_engine_stop_net_log().
// Returns non-zero on success. `log_all` includes socket bytes and cookies.
CRONET_EXPORT int32_t cronet_engine_start_net_log(cronet_engine* engine,
                                                  const char* path,
                                                  int32_t log_all);
CRONET_EXPORT void cronet_engine_stop_net_log(cronet_engine* engine);

// ---------------------------------------------------------------------------
// Calls
// ---------------------------------------------------------------------------

typedef struct cronet_call cronet_call;

// Request priority, lowest to highest; CRONET_PRIORITY_MEDIUM is Chromium's
// default for a main-frame fetch.
typedef enum {
  CRONET_PRIORITY_THROTTLED = 0,
  CRONET_PRIORITY_IDLE = 1,
  CRONET_PRIORITY_LOWEST = 2,
  CRONET_PRIORITY_LOW = 3,
  CRONET_PRIORITY_MEDIUM = 4,
  CRONET_PRIORITY_HIGHEST = 5,
} cronet_priority;

typedef struct {
  const char* method;  // Empty means "GET".
  const char* url;
  // Sent in this order, as one block. Chromium puts Host and Connection ahead
  // of the block and appends the rest of its own headers after it. Setting a
  // header here replaces Chromium's value in the position Chromium gave it,
  // rather than adding a second copy.
  const cronet_header* headers;
  size_t header_count;
  const uint8_t* body;  // Borrowed only for the duration of cronet_call_start.
  size_t body_size;
  int32_t priority;  // A cronet_priority.
  // How many redirects to follow. Negative for Chromium's default of 20. Zero
  // returns the first redirect itself, unfollowed, as a successful response.
  // Running past a non-zero limit fails with CRONET_ERROR_TOO_MANY_REDIRECTS.
  int32_t max_redirects;
  int32_t disable_cache;  // Non-zero to skip the engine's cache for this call.
} cronet_request;

// Fills `request` with the library defaults, as cronet_engine_config_init does.
CRONET_EXPORT void cronet_request_init(cronet_request* request);

// Timings, in *microseconds* since the Unix epoch — Cronet's own metrics are
// microseconds despite its comments saying otherwise, and the resolution is
// worth keeping. CRONET_NO_TIME when the phase did not happen, as a reused
// socket has no dns_start.
#define CRONET_NO_TIME (-1)

typedef struct {
  int64_t request_start_us;
  int64_t dns_start_us;
  int64_t dns_end_us;
  int64_t connect_start_us;
  int64_t connect_end_us;
  int64_t ssl_start_us;
  int64_t ssl_end_us;
  int64_t send_start_us;
  int64_t send_end_us;
  int64_t response_start_us;
  int64_t request_end_us;
  int64_t sent_bytes;
  int64_t received_bytes;
  int32_t socket_reused;
} cronet_metrics;

typedef struct {
  int32_t status_code;  // 0 when the call failed before a response arrived.
  const char* status_text;
  const cronet_header* headers;  // In the order the server sent them.
  size_t header_count;
  // "http/1.1", "h2" or "h3" once ALPN has run. "unknown" when it has not, as
  // on any plaintext HTTP connection.
  const char* negotiated_protocol;
  // Host and port of the proxy, without a scheme, as Chromium reports it.
  // ":0" when the connection went direct.
  const char* proxy_server;
  const char* final_url;            // The last URL, after any redirects.
  int32_t redirect_count;
  int32_t was_cached;
  // 0 when the call succeeded. Otherwise a Chromium net error (negative), or
  // CRONET_ERROR_TOO_MANY_REDIRECTS. A call has no deadline of its own, so
  // CRONET_ERROR_TIMED_OUT never appears here — it is defined for callers that
  // impose one with cronet_call_wait() and need a code to report it under.
  int32_t error_code;
  const char* error_message;
  cronet_metrics metrics;
} cronet_response;

// Errors this library sets itself. The first two reuse the Chromium code of
// the same meaning. The redirect one is this library's own number because the
// limit is this library's own too: the observer in call.cc stops the chain and
// reports it, so net::ERR_TOO_MANY_REDIRECTS never reaches a caller from here.
// -31 also sits outside the ranges a caller tests to sort connection (-100 to
// -199) from certificate (-200 to -299) failures, so it cannot be read as one.
#define CRONET_ERROR_ABORTED (-3)              // net::ERR_ABORTED
#define CRONET_ERROR_TIMED_OUT (-7)            // net::ERR_TIMED_OUT
#define CRONET_ERROR_TOO_MANY_REDIRECTS (-31)  // This library's own.

// Starts a call and returns immediately. Returns NULL only when `request` is
// malformed (no URL, or a URL Chromium cannot parse); every other failure,
// including a connection that never opens, arrives as a response with a
// non-zero error_code.
//
// Nothing in `request` is retained: the strings and body may be freed as soon
// as this returns.
CRONET_EXPORT cronet_call* cronet_call_start(cronet_engine* engine,
                                             const cronet_request* request);

// How far a call has got. A call only ever moves forward through these.
typedef enum {
  CRONET_CALL_STARTED = 0,  // Nothing has arrived yet.
  CRONET_CALL_HEADERS = 1,  // cronet_call_response() is readable; body may be
                            // arriving.
  CRONET_CALL_DONE = 2,     // Finished, successfully or not. The body is
                            // complete once cronet_call_read() reports
                            // CRONET_EOF, which may be before this.
} cronet_call_state;

CRONET_EXPORT int32_t cronet_call_state_of(const cronet_call* call);

// A file descriptor that becomes readable when the call makes progress: the
// headers arrive, body bytes become available, or the call finishes. Owned by
// the call; do not close it.
//
// It is an eventfd counter, so a wakeup is never lost. Drain it with a single
// 8-byte read *before* reading the body, then read until cronet_call_read()
// returns 0; anything that arrives in between leaves the descriptor readable
// and the next wait returns at once.
CRONET_EXPORT int cronet_call_fd(const cronet_call* call);

// Blocks until the call finishes or `timeout_ms` elapses; negative waits
// forever, 0 polls. Returns non-zero once the call has finished. Waits on the
// call's own event, so it neither consumes nor is disturbed by
// cronet_call_fd().
CRONET_EXPORT int32_t cronet_call_wait(cronet_call* call, int32_t timeout_ms);

// The status line, headers and metadata, or NULL until the headers have
// arrived. Carries no body: the body is streamed with cronet_call_read().
// Owned by the call and valid until cronet_call_free().
CRONET_EXPORT const cronet_response* cronet_call_response(cronet_call* call);

// Returned by cronet_call_read() once the whole body has been handed over.
#define CRONET_EOF (-1)

// Copies at most `capacity` bytes of the response body into `buffer`.
//
// Returns the number of bytes copied; 0 when none are buffered right now,
// which is not the end — wait on cronet_call_fd() and read again; or
// CRONET_EOF once the body is complete.
//
// This is the only way to read a body, and it is what applies backpressure:
// the library buffers a bounded amount and stops reading from the network
// until this drains it, so a consumer that reads slowly slows the transfer
// down instead of growing memory without limit. A caller that wants the whole
// body simply reads in a loop until CRONET_EOF.
CRONET_EXPORT int64_t cronet_call_read(cronet_call* call,
                                       uint8_t* buffer,
                                       size_t capacity);

// Asks for the call to stop. It finishes with CRONET_ERROR_ABORTED unless it
// had already completed. Returns without waiting.
CRONET_EXPORT void cronet_call_cancel(cronet_call* call);

// Cancels the call if it is still running, waits for the network thread to let
// go of it, and frees it along with its response. Every call from
// cronet_call_start() must be passed here exactly once.
CRONET_EXPORT void cronet_call_free(cronet_call* call);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // CRONET_H_
