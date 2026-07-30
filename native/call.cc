// CallState, and the observer Chromium calls back into.
//
// Which thread runs what is the thing to hold on to while reading: everything
// in the anonymous namespace below is called on the network thread, and
// CallState's read and wait methods are called on the owner's. The locks exist
// only where those two meet — around the body buffer, and around the request
// pointer, which the owner may ask to destroy while a callback is still in
// flight.

#include "call.h"

#include <errno.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <algorithm>
#include <memory>
#include <utility>

#include "base/containers/span.h"
#include "base/posix/eintr_wrapper.h"
#include "base/time/time.h"
#include "components/cronet/metrics_util.h"
#include "engine.h"
#include "net/base/elements_upload_data_stream.h"
#include "net/base/idempotency.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/base/upload_bytes_element_reader.h"
#include "net/http/http_response_headers.h"
#include "url/gurl.h"

namespace cronet_standalone {
namespace {

// Large enough that a fast response needs few round trips through the network
// thread, small enough not to matter for a small one.
constexpr int kReadBufferSize = 64 * 1024;

// Runs on the network thread for the whole life of one request, recording what
// it sees into the CallState it shares with the request's owner. Owned by the
// CronetURLRequest, and deleted with it.
class RequestObserver : public cronet::CronetURLRequest::Callback {
 public:
  RequestObserver(scoped_refptr<CallState> state,
                  Engine* engine,
                  int max_redirects)
      : state_(std::move(state)),
        engine_(engine),
        max_redirects_(max_redirects) {}

  RequestObserver(const RequestObserver&) = delete;
  RequestObserver& operator=(const RequestObserver&) = delete;

  ~RequestObserver() override = default;

 private:
  void OnReceivedRedirect(const std::string& new_location,
                          int http_status_code,
                          const std::string& http_status_text,
                          const net::HttpResponseHeaders* headers,
                          bool was_cached,
                          const std::string& negotiated_protocol,
                          const std::string& proxy_server,
                          int64_t received_byte_count) override {
    if (redirect_count_ >= max_redirects_) {
      // Hand back the redirect itself, so the caller can read its Location
      // either way. Asking for no redirects at all is a choice and succeeds;
      // running out part way through a chain is a failure.
      state_->OnResponse(http_status_code, http_status_text, headers, was_cached,
                         negotiated_protocol, proxy_server);
      state_->set_redirect_count(redirect_count_);
      if (max_redirects_ == 0) {
        state_->Finish(0, std::string());
      } else {
        state_->Finish(CRONET_ERROR_TOO_MANY_REDIRECTS,
                       "redirect limit reached at " + new_location);
      }
      state_->DestroyWithoutCancel();
      return;
    }
    ++redirect_count_;
    state_->OnRedirect(new_location);
    state_->FollowRedirect();
  }

  void OnResponseStarted(int http_status_code,
                         const std::string& http_status_text,
                         const net::HttpResponseHeaders* headers,
                         bool was_cached,
                         const std::string& negotiated_protocol,
                         const std::string& proxy_server,
                         int64_t received_byte_count,
                         bool is_proxied) override {
    state_->OnResponse(http_status_code, http_status_text, headers, was_cached,
                       negotiated_protocol, proxy_server);
    state_->set_redirect_count(redirect_count_);
    state_->ReadData(state_->read_buffer(), state_->read_buffer_size());
  }

  void OnReadCompleted(scoped_refptr<net::IOBuffer> buffer,
                       int bytes_read,
                       int64_t received_byte_count) override {
    // OnData answers whether there is room for more. When there is not, the
    // read is deliberately not re-issued here: the consumer restarts it by
    // draining, and until it does the socket's window closes and the server
    // slows down. That is the whole of the backpressure.
    if (state_->OnData(buffer->data(), static_cast<size_t>(bytes_read))) {
      state_->ReadData(state_->read_buffer(), state_->read_buffer_size());
    }
  }

  void OnSucceeded(int64_t received_byte_count) override {
    state_->Finish(0, std::string());
    state_->DestroyWithoutCancel();
  }

  void OnError(int net_error,
               int quic_error,
               quic::ConnectionCloseSource source,
               const std::string& error_string,
               int64_t received_byte_count) override {
    state_->Finish(net_error, error_string.empty()
                                  ? net::ErrorToString(net_error)
                                  : error_string);
    state_->DestroyWithoutCancel();
  }

  void OnCanceled() override {
    state_->Finish(CRONET_ERROR_ABORTED, "the call was cancelled");
  }

  void OnDestroyed() override {
    // A last resort: no path should reach here without a terminal callback,
    // and a caller waiting on a call that never finishes would hang forever.
    state_->Finish(CRONET_ERROR_ABORTED, "the call ended without a result");
    // Unregister before releasing, and with no lock of our own held, so that
    // an engine shutting down can never wait on a lock we are holding.
    engine_->UnregisterCall(state_.get());
    state_->OnReleased();
  }

  void OnMetricsCollected(const base::Time& request_start_time,
                          const base::TimeTicks& request_start,
                          const base::TimeTicks& dns_start,
                          const base::TimeTicks& dns_end,
                          const base::TimeTicks& connect_start,
                          const base::TimeTicks& connect_end,
                          const base::TimeTicks& ssl_start,
                          const base::TimeTicks& ssl_end,
                          const base::TimeTicks& send_start,
                          const base::TimeTicks& send_end,
                          const base::TimeTicks& push_start,
                          const base::TimeTicks& push_end,
                          const base::TimeTicks& receive_headers_end,
                          const base::TimeTicks& request_end,
                          bool socket_reused,
                          int64_t sent_bytes_count,
                          int64_t received_bytes_count,
                          bool quic_connection_migration_attempted,
                          bool quic_connection_migration_successful) override {
    // Cronet's ConvertTime returns microseconds since the Unix epoch, whatever
    // its own comment says; verified in components/cronet/metrics_util.cc.
    auto to_epoch_us = [&](const base::TimeTicks& ticks) {
      return cronet::metrics_util::ConvertTime(ticks, request_start,
                                               request_start_time);
    };
    cronet_metrics metrics = {};
    metrics.request_start_us = to_epoch_us(request_start);
    metrics.dns_start_us = to_epoch_us(dns_start);
    metrics.dns_end_us = to_epoch_us(dns_end);
    metrics.connect_start_us = to_epoch_us(connect_start);
    metrics.connect_end_us = to_epoch_us(connect_end);
    metrics.ssl_start_us = to_epoch_us(ssl_start);
    metrics.ssl_end_us = to_epoch_us(ssl_end);
    metrics.send_start_us = to_epoch_us(send_start);
    metrics.send_end_us = to_epoch_us(send_end);
    metrics.response_start_us = to_epoch_us(receive_headers_end);
    metrics.request_end_us = to_epoch_us(request_end);
    metrics.sent_bytes = sent_bytes_count;
    metrics.received_bytes = received_bytes_count;
    metrics.socket_reused = socket_reused ? 1 : 0;
    state_->set_metrics(metrics);
  }

  const scoped_refptr<CallState> state_;
  const raw_ptr<Engine> engine_;
  const int max_redirects_;
  int redirect_count_ = 0;
};

}  // namespace

void ResponseStorage::Publish() {
  headers.clear();
  headers.reserve(header_names.size());
  for (size_t i = 0; i < header_names.size(); ++i) {
    headers.push_back({header_names[i].c_str(), header_values[i].c_str()});
  }
  view.status_text = status_text.c_str();
  view.headers = headers.data();
  view.header_count = headers.size();
  view.negotiated_protocol = negotiated_protocol.c_str();
  view.proxy_server = proxy_server.c_str();
  view.final_url = final_url.c_str();
  // error_message is deliberately not published here. It is written once, in
  // Finish(), and read only after the call reports CRONET_CALL_DONE, so the
  // string is never reassigned while a caller might hold a pointer into it.
}

CallState::CallState()
    : completion_fd_(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK)),
      read_buffer_(
          base::MakeRefCounted<net::IOBufferWithSize>(kReadBufferSize)) {
  CHECK_GE(completion_fd_, 0) << "eventfd failed: " << errno;
  // Zeroed as bytes, not member by member: the struct crosses the ABI whole,
  // and member-wise initialisation leaves its padding holding whatever the
  // allocator last had there.
  std::ranges::fill(
      base::byte_span_from_ref(base::allow_nonunique_obj, response_.view),
      uint8_t{0});
}

CallState::~CallState() {
  close(completion_fd_);
}

void CallState::SignalProgress() {
  const uint64_t token = 1;
  const ssize_t written =
      HANDLE_EINTR(write(completion_fd_, &token, sizeof(token)));
  // EAGAIN means the counter is already at its maximum, so the descriptor is
  // readable anyway and a dropped increment changes nothing.
  PCHECK(written == static_cast<ssize_t>(sizeof(token)) || errno == EAGAIN);
}

bool CallState::Wait(int32_t timeout_ms) {
  if (is_finished()) {
    return true;
  }
  if (timeout_ms == 0) {
    return false;
  }
  if (timeout_ms < 0) {
    finished_.Wait();
    return true;
  }
  return finished_.TimedWait(base::Milliseconds(timeout_ms));
}

const cronet_response* CallState::response() const {
  // Readable from the headers onwards, and on a call that failed before any
  // arrived — Finish() publishes the storage in that case, so the error is
  // still there to read.
  return state_.load(std::memory_order_acquire) == CRONET_CALL_STARTED
             ? nullptr
             : &response_.view;
}

int64_t CallState::Read(uint8_t* out, size_t capacity) {
  if (capacity == 0) {
    return 0;
  }
  int64_t copied = 0;
  bool should_resume = false;
  {
    base::AutoLock auto_lock(body_lock_);
    const size_t available = body_.size() - body_offset_;
    if (available == 0) {
      return body_complete_ ? CRONET_EOF : 0;
    }
    copied = static_cast<int64_t>(std::min(capacity, available));
    body_.copy(reinterpret_cast<char*>(out), static_cast<size_t>(copied),
               body_offset_);
    body_offset_ += static_cast<size_t>(copied);

    // Reclaim the front once more has been handed out than is left, so a long
    // download does not drag the whole transfer along behind it.
    if (body_offset_ > body_.size() - body_offset_) {
      body_.erase(0, body_offset_);
      body_offset_ = 0;
    }
    if (read_paused_ && body_.size() - body_offset_ <= kLowWaterBytes) {
      read_paused_ = false;
      should_resume = true;
    }
  }
  if (should_resume) {
    // Outside body_lock_: ReadData takes the request lock, and the two are
    // never held at once.
    ReadData(read_buffer_.get(), read_buffer_->size());
  }
  return copied;
}

void CallState::AttachRequest(cronet::CronetURLRequest* request) {
  base::AutoLock auto_lock(lock_);
  request_ = request;
}

void CallState::Cancel() {
  DestroyRequest(/*send_on_canceled=*/true);
}

void CallState::DestroyWithoutCancel() {
  DestroyRequest(/*send_on_canceled=*/false);
}

bool CallState::ReadData(net::IOBuffer* buffer, int size) {
  base::AutoLock auto_lock(lock_);
  if (destroy_requested_ || !request_) {
    return false;
  }
  request_->ReadData(buffer, size);
  return true;
}

bool CallState::FollowRedirect() {
  base::AutoLock auto_lock(lock_);
  if (destroy_requested_ || !request_) {
    return false;
  }
  request_->FollowDeferredRedirect();
  return true;
}

void CallState::DestroyRequest(bool send_on_canceled) {
  base::AutoLock auto_lock(lock_);
  if (destroy_requested_ || !request_) {
    return;
  }
  destroy_requested_ = true;
  // Destroy() only posts to the network thread, so it cannot re-enter us.
  request_->Destroy(send_on_canceled);
}

void CallState::WaitForRelease() {
  released_.Wait();
}

void CallState::OnReleased() {
  {
    base::AutoLock auto_lock(lock_);
    request_ = nullptr;
  }
  released_.Signal();
}

void CallState::set_initial_url(const std::string& url) {
  response_.final_url = url;
}

void CallState::OnRedirect(const std::string& location) {
  response_.final_url = location;
}

void CallState::OnResponse(int status_code,
                           const std::string& status_text,
                           const net::HttpResponseHeaders* headers,
                           bool was_cached,
                           const std::string& negotiated_protocol,
                           const std::string& proxy_server) {
  response_.view.status_code = status_code;
  response_.view.was_cached = was_cached ? 1 : 0;
  response_.status_text = status_text;
  response_.negotiated_protocol = negotiated_protocol;
  response_.proxy_server = proxy_server;

  response_.header_names.clear();
  response_.header_values.clear();
  if (headers) {
    size_t iterator = 0;
    std::string name;
    std::string value;
    while (headers->EnumerateHeaderLines(&iterator, &name, &value)) {
      response_.header_names.push_back(std::move(name));
      response_.header_values.push_back(std::move(value));
    }
  }

  // Published before the state moves, so that a caller which sees
  // CRONET_CALL_HEADERS finds every pointer already pointing somewhere.
  response_.Publish();
  headers_published_ = true;
  state_.store(CRONET_CALL_HEADERS, std::memory_order_release);
  SignalProgress();
}

bool CallState::OnData(const char* data, size_t size) {
  bool keep_reading;
  {
    base::AutoLock auto_lock(body_lock_);
    body_.append(data, size);
    keep_reading = body_.size() - body_offset_ < kHighWaterBytes;
    read_paused_ = !keep_reading;
  }
  SignalProgress();
  return keep_reading;
}

void CallState::set_metrics(const cronet_metrics& metrics) {
  // Cronet reports metrics from its teardown task, which on the redirect-limit
  // path runs after the result was already published. Writing then would be a
  // write racing the owner's read, so the last word goes to whoever published.
  if (is_finished()) {
    return;
  }
  response_.view.metrics = metrics;
}

void CallState::set_redirect_count(int count) {
  response_.view.redirect_count = count;
}

void CallState::Finish(int error_code, const std::string& error_message) {
  // Only the first outcome counts: a cancellation racing a completion must not
  // rewrite a result the owner may already be reading. Claimed with an
  // exchange rather than a load and a store, which two threads could both
  // pass.
  if (outcome_claimed_.exchange(true, std::memory_order_relaxed)) {
    return;
  }
  {
    base::AutoLock auto_lock(body_lock_);
    body_complete_ = true;
    // Nothing further will be read from the network, so a reader that paused
    // at the high-water mark must not wait for a resume that cannot come.
    read_paused_ = false;
  }
  // A call that failed before any headers arrived has never been published, so
  // publish it now. No caller can have read it yet, the state having been
  // CRONET_CALL_STARTED throughout.
  if (!headers_published_) {
    response_.Publish();
    headers_published_ = true;
  }
  response_.error_message = error_message;
  response_.view.error_message = response_.error_message.c_str();
  response_.view.error_code = error_code;

  state_.store(CRONET_CALL_DONE, std::memory_order_release);
  finished_.Signal();
  SignalProgress();
}

scoped_refptr<CallState> StartCall(Engine* engine, const RequestSpec& spec) {
  const GURL url(spec.url);
  if (!url.is_valid()) {
    return nullptr;
  }

  auto state = base::MakeRefCounted<CallState>();
  state->set_initial_url(spec.url);
  if (!engine->RegisterCall(state.get())) {
    return nullptr;
  }

  // Owns itself from here on: the request is freed by its own Destroy(), which
  // takes the observer with it.
  auto* request = new cronet::CronetURLRequest(
      engine->context(),
      std::make_unique<RequestObserver>(
          state, engine, spec.max_redirects < 0 ? 20 : spec.max_redirects),
      url, spec.priority, spec.disable_cache,
      /*disable_connection_migration=*/false,
      /*traffic_stats_tag_set=*/false, /*traffic_stats_tag=*/0,
      /*traffic_stats_uid_set=*/false, /*traffic_stats_uid=*/0,
      net::DEFAULT_IDEMPOTENCY, /*shared_dictionary=*/nullptr);

  // Configured before it is published: once AttachRequest has run, another
  // thread may cancel, and a cancel landing between two of these calls would
  // tear the request down half-configured.
  request->SetHttpMethod(spec.method);
  for (const auto& [name, value] : spec.headers) {
    request->AddRequestHeader(name, value);
  }
  if (!spec.body.empty()) {
    request->SetUpload(net::ElementsUploadDataStream::CreateWithReader(
        net::UploadOwnedBytesElementReader::CreateWithString(spec.body)));
  }
  state->AttachRequest(request);
  request->Start();
  return state;
}

}  // namespace cronet_standalone
