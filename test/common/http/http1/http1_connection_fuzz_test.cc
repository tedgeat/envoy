#include "source/common/http/conn_manager_utility.h"
#include "source/common/http/exception.h"
#include "source/common/http/header_map_impl.h"
#include "source/common/http/http1/codec_impl.h"

#include "test/fuzz/fuzz_runner.h"
#include "test/fuzz/utility.h"
#include "test/mocks/http/mocks.h"
#include "test/mocks/network/mocks.h"
#include "test/mocks/server/overload_manager.h"
#include "test/test_common/test_runtime.h"

#include "absl/strings/substitute.h"
#include "gmock/gmock.h"

using testing::_;
using testing::Invoke;

namespace Envoy {
namespace Http {
namespace Http1 {
namespace {

static Http1Settings fromHttp1Settings(bool use_balsa) {
  Http1Settings h1_settings;
  h1_settings.allow_absolute_url_ = true;
  h1_settings.accept_http_10_ = true;
  h1_settings.default_host_for_http_10_ = "localhost";
  h1_settings.enable_trailers_ = true;
  h1_settings.stream_error_on_invalid_http_message_ = true;
  h1_settings.use_balsa_parser_ = use_balsa;
  return h1_settings;
}

class Http1Harness {
public:
  Http1Harness() {
    ON_CALL(mock_server_callbacks_, newStream(_, _))
        .WillByDefault(Invoke(
            [&](ResponseEncoder&, bool) -> RequestDecoder& { return orphan_request_decoder_; }));
  }

  void fuzzResponse(Buffer::Instance& payload, bool use_balsa) {
    auto client_settings = fromHttp1Settings(use_balsa);
    client_ = std::make_unique<Http1::ClientConnectionImpl>(
        mock_client_connection_,
        Http1::CodecStats::atomicGet(http1_stats_, *stats_store_.rootScope()),
        mock_client_callbacks_, client_settings, absl::nullopt, Http::DEFAULT_MAX_HEADERS_COUNT);
    Status status = client_->dispatch(payload);
  }

  void fuzzRequest(Buffer::Instance& payload, bool use_balsa) {
    auto server_settings = fromHttp1Settings(use_balsa);
    server_ = std::make_unique<Http1::ServerConnectionImpl>(
        mock_server_connection_,
        Http1::CodecStats::atomicGet(http1_stats_, *stats_store_.rootScope()),
        mock_server_callbacks_, server_settings, Http::DEFAULT_MAX_REQUEST_HEADERS_KB,
        Http::DEFAULT_MAX_HEADERS_COUNT, envoy::config::core::v3::HttpProtocolOptions::ALLOW,
        overload_manager_);

    Status status = server_->dispatch(payload);
  }

private:
  Stats::IsolatedStoreImpl stats_store_;
  Http1::CodecStats::AtomicPtr http1_stats_;

  NiceMock<MockConnectionCallbacks> mock_client_callbacks_;
  NiceMock<Network::MockConnection> mock_client_connection_;
  ClientConnectionPtr client_;

  NiceMock<MockRequestDecoder> orphan_request_decoder_;
  NiceMock<Network::MockConnection> mock_server_connection_;
  NiceMock<MockServerConnectionCallbacks> mock_server_callbacks_;
  testing::NiceMock<Server::MockOverloadManager> overload_manager_;

  ServerConnectionPtr server_;
};

static std::unique_ptr<Http1Harness> harness;
static void resetHarness() { harness = nullptr; }

// Fuzzing strategy
// Unconstrained fuzzing, rely on corpus for coverage

DEFINE_FUZZER(const uint8_t* buf, size_t len) {
  if (harness == nullptr) {
    harness = std::make_unique<Http1Harness>();
    atexit(resetHarness);
  }

  Buffer::OwnedImpl httpmsg;
  httpmsg.add(buf, len);
  // HTTP requests and responses are handled differently in the codec, hence we
  // setup two instances of the parser, which do not interact.
  harness->fuzzRequest(httpmsg, false);
  harness->fuzzResponse(httpmsg, false);
  harness->fuzzRequest(httpmsg, true);
  harness->fuzzResponse(httpmsg, true);
}

} // namespace
} // namespace Http1
} // namespace Http
} // namespace Envoy
