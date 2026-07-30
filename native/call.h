// One request in flight, and the state its two threads share.
//
// A call is owned by whichever thread started it and filled in by Chromium's
// network thread, and neither ever calls into the other: they meet only at
// CallState, and the owner learns that something happened by finding a
// descriptor readable rather than by having a callback run underneath it. That
// is what lets one call be waited on by a blocking read and another by an event
// loop, with the library knowing about neither.
//
// CallState's public methods are grouped by which side may call them, because
// that grouping is the whole of the thread-safety argument.

#ifndef CRONET_STANDALONE_CALL_H_
#define CRONET_STANDALONE_CALL_H_

#include <stdint.h>

#include <atomic>
#include <string>
#include <utility>
#include <vector>

#include "base/memory/raw_ptr.h"
#include "base/memory/ref_counted.h"
#include "base/memory/scoped_refptr.h"
#include "base/synchronization/lock.h"
#include "base/synchronization/waitable_event.h"
#include "components/cronet/cronet_url_request.h"
#include "cronet.h"
#include "net/base/io_buffer.h"
#include "net/base/request_priority.h"

namespace cronet_standalone {

class Engine;

struct RequestSpec {
  std::string method = "GET";
  std::string url;
  std::vector<std::pair<std::string, std::string>> headers;
  std::string body;
  net::RequestPriority priority = net::MEDIUM;
  int max_redirects = 20;
  bool disable_cache = false;
};

// Backing store for the response handed out through the C ABI: `view` points
// into the strings beside it, so the whole struct has to outlive every pointer
// the caller reads out of it. The body is not here — it streams out of
// CallState's buffer rather than being accumulated whole.
struct ResponseStorage {
  cronet_response view = {};
  std::string status_text;
  std::string negotiated_protocol;
  std::string proxy_server;
  std::string final_url;
  std::string error_message;
  std::vector<std::string> header_names;
  std::vector<std::string> header_values;
  std::vector<cronet_header> headers;

  // Points `view` at the storage beside it. Called once, before the call is
  // published as having reached its headers.
  void Publish();
};

// Everything one call owns that crosses threads. Reference counted because
// either side may be the last to let go: the network thread finishes a request
// whose owner may already be waiting to free it, and the owner may free a call
// the network thread has not finished unwinding.
class CallState : public base::RefCountedThreadSafe<CallState> {
 public:
  // How much body is held before the library stops reading from the network,
  // and the level at which it resumes. Two marks rather than one so that a
  // consumer reading in small pieces does not toggle the request on and off
  // on every read.
  static constexpr size_t kHighWaterBytes = 256 * 1024;
  static constexpr size_t kLowWaterBytes = 64 * 1024;

  CallState();

  CallState(const CallState&) = delete;
  CallState& operator=(const CallState&) = delete;

  // --- Owner side; any thread ---

  // Readable whenever the call makes progress: headers arrive, body bytes
  // become available, or the call ends. Owned by `this`.
  int completion_fd() const { return completion_fd_; }

  bool is_finished() const {
    return state_.load(std::memory_order_acquire) == CRONET_CALL_DONE;
  }

  int32_t state() const { return state_.load(std::memory_order_acquire); }

  // Blocks until the call finishes or `timeout_ms` runs out; negative waits
  // forever, zero polls. Returns whether the call has finished. Waits on its
  // own event rather than on the descriptor, so draining the descriptor for
  // the streaming path cannot make this spin.
  bool Wait(int32_t timeout_ms);

  // Null until the headers have arrived.
  const cronet_response* response() const;

  // Copies out at most `capacity` body bytes. Returns how many were copied, 0
  // when none are buffered right now, or CRONET_EOF once the body is
  // complete. Draining below the low-water mark resumes the network read,
  // which is what makes the consumer's pace set the transfer's pace.
  int64_t Read(uint8_t* out, size_t capacity);

  // Asks the network thread to abandon the request. Returns at once.
  void Cancel();

  // Blocks until the network thread has destroyed the request, after which no
  // further callback can arrive.
  void WaitForRelease();

  // --- Network thread only ---

  // Ask the request for more body, or to follow the redirect it is holding.
  // Both return false once teardown has been asked for.
  //
  // These take the lock even though they are called from the network thread,
  // and that is the whole point. Both post a task bound to the request, and
  // CronetURLRequest requires that Destroy() be posted "from within a
  // synchronized block that guarantees no future posts to the network thread
  // with the request pointer". Posting from outside the lock lets the queue
  // reach [Destroy, ReadData], and the read then runs on a freed request.
  //
  // ReadData also posts, which is what lets a read be resumed from the
  // consumer's thread when it drains the buffer.
  bool ReadData(net::IOBuffer* buffer, int size);
  bool FollowRedirect();

  // The buffer body reads land in. Owned here rather than by the observer
  // because a paused read is restarted by whichever thread drains the buffer.
  net::IOBuffer* read_buffer() { return read_buffer_.get(); }
  int read_buffer_size() const { return read_buffer_->size(); }

  void set_initial_url(const std::string& url);
  void OnRedirect(const std::string& location);
  void OnResponse(int status_code,
                  const std::string& status_text,
                  const net::HttpResponseHeaders* headers,
                  bool was_cached,
                  const std::string& negotiated_protocol,
                  const std::string& proxy_server);

  // Takes in body bytes. Returns whether the network should keep reading:
  // false once the buffer has filled, after which Read() restarts it.
  bool OnData(const char* data, size_t size);

  void set_metrics(const cronet_metrics& metrics);
  void set_redirect_count(int count);

  // Records the outcome and wakes the owner. Only the first call counts, so a
  // cancellation racing a completion cannot rewrite the result.
  void Finish(int error_code, const std::string& error_message);

  // Called from the request's last callback, once it is about to be deleted.
  void OnReleased();

  // Handed the request before it starts, so that Cancel() has something to
  // act on.
  void AttachRequest(cronet::CronetURLRequest* request);

  // Tears the request down without reporting it as a cancellation, which is
  // what a call that has already recorded its outcome wants.
  void DestroyWithoutCancel();

 private:
  friend class base::RefCountedThreadSafe<CallState>;
  ~CallState();

  void DestroyRequest(bool send_on_canceled);

  // Makes completion_fd() readable. The descriptor is an eventfd counter, so
  // signalling while the owner sits between a drain and a read leaves it
  // readable and the next wait returns at once — a wakeup is never lost.
  void SignalProgress();

  // An eventfd rather than a condition variable: an event loop can wait on a
  // descriptor, and no callback ever has to run on a network thread.
  const int completion_fd_;

  // Claimed by whichever outcome arrives first. Separate from `state_`
  // because a load-then-store pair is not atomic: two threads could both read
  // "not finished" and both go on to record a result.
  std::atomic<bool> outcome_claimed_{false};

  // Publishes `response_`. The owner acquires it and reads no part of the
  // response before the state that publishes that part has been reached.
  std::atomic<int32_t> state_{CRONET_CALL_STARTED};

  base::WaitableEvent finished_;
  base::WaitableEvent released_;

  // Written on the network thread, read by the owner only once `state_` says
  // the part being read has been published.
  ResponseStorage response_;
  bool headers_published_ = false;

  // The body in flight between the network and the consumer. `body_offset_`
  // is how much of `body_` has already been handed out; the front is reclaimed
  // once it has grown past what is left, so a long download does not carry the
  // whole transfer around behind it.
  base::Lock body_lock_;
  std::string body_ GUARDED_BY(body_lock_);
  size_t body_offset_ GUARDED_BY(body_lock_) = 0;
  bool body_complete_ GUARDED_BY(body_lock_) = false;
  bool read_paused_ GUARDED_BY(body_lock_) = false;

  const scoped_refptr<net::IOBufferWithSize> read_buffer_;

  base::Lock lock_;
  raw_ptr<cronet::CronetURLRequest> request_ GUARDED_BY(lock_) = nullptr;
  bool destroy_requested_ GUARDED_BY(lock_) = false;
};

// Starts `spec` on `engine`. Returns null when the URL is unusable or the
// engine is shutting down.
scoped_refptr<CallState> StartCall(Engine* engine, const RequestSpec& spec);

}  // namespace cronet_standalone

#endif  // CRONET_STANDALONE_CALL_H_
