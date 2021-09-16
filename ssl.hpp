#pragma once

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "debug.hpp"

namespace ssl {
  static debugging::Debug* debug = new debugging::Debug("ssl", debugging::colors::cyan);

  void enableDebug() {
    debug->enable();
  }

  void disableDebug() {
    debug->disable();
  }

  template <typename ...A>
    void log(pstd::vstring str, A ...args) {
      debug->log(str, args ...);
    }

  // ----

  struct exception : public pstd::exception {
    public:
      template <typename ...A>
        exception(pstd::vstring str, A ...args) : pstd::exception(str, args ...) {

        }
  };

  enum class event {
    ERROR = EOF,
    DISCONNECTED
  };

  enum class status {
    FAIL = EOF,
    OK
  };

  // ----

  static bool initalized = !1;

  // ----

  void init() {
    if (initalized)
      return;

    log("initializing ssl");

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    initalized = !0;
  }

  SSL* wrapOutgoing(uint id) {
    init();

    log("creating socket ssl client and method");

    auto method = TLS_client_method();
    auto context = SSL_CTX_new(method);
    auto ssl = SSL_new(context);

    if (!ssl)
      throw exception("unable to create SSL");

    log("socket id set to %i", id);

    auto i = SSL_set_fd(ssl, id);

    if (i == 0)
      throw exception("unable to set id");

    return ssl;
  }

  std::pair<SSL_CTX*, SSL*> wrapServer(uint id) {
    init();

    log("creating socket ssl server and method");

    auto method = TLS_server_method();
    auto context = SSL_CTX_new(method);
    auto ssl = SSL_new(context);

    if (!ssl)
      throw exception("unable to create SSL");

    log("server id set to %i", id);

    SSL_set_fd(ssl, id);

    return {
      context,
      ssl
    };
  }

  SSL* wrapIncoming(uint id, SSL_CTX* ctx) {
    init();

    log("creating socket ssl client");

    auto ssl = SSL_new(ctx);

    if (!ssl)
      throw exception("unable to create SSL");

    log("socket id set to %i", id);

    SSL_set_fd(ssl, id);

    return ssl;
  }

  void loadPEMCert(SSL_CTX* &ctx, pstd::vstring cert, pstd::vstring privkey) {
    log("assigning certificate and privkey");

    pstd::log(cert);

    auto i = SSL_CTX_use_certificate_file(ctx, &cert[0], SSL_FILETYPE_PEM);
    if (i != 1)
      throw exception("unable to use cert file");

    i = SSL_CTX_use_PrivateKey_file(ctx, &privkey[0], SSL_FILETYPE_PEM);

    if (i != 1)
      throw exception("unable to use key file");

    i = SSL_CTX_check_private_key(ctx);

    if (!i)
      throw exception("privkey does not match public cert");
  }

  std::variant<event, std::string> recv(SSL* id, uint size = 1024) {
    log("recieving data");

    auto buffer = std::vector<char>(size);
    auto recvd = std::string("");
    auto len = int(0);

    while (!0) {
      auto i = SSL_read(id, &buffer[0], size);

      log("recieved data length %i", i);

      if (i == EOF) {
        if (errno == EAGAIN)
          continue;

        return event::ERROR;
      }

      if (i == 0)
        return event::DISCONNECTED;

      auto begin = std::begin(buffer);
      auto end = std::end(buffer);
      
      recvd += std::string(begin, end);
      buffer.clear();
      len += i;

      if (i < size)
        return recvd.substr(0, len);
    }
  }

  template <typename ...A>
    void send(SSL* id, pstd::vstring text, A ...args) {
      log("sending data");

      auto out = pstd::format(text, args ...);
      auto offset = 0;

      while (offset < out.length())
        offset += ::SSL_write(id, out.substr(offset).data(), out.substr(offset).length(), 0);
    }

  status accept(SSL* id) {
    log("accepting next incoming connection");

    auto i = SSL_accept(id);

    return i != EOF ?
      status::OK : status::FAIL;
  }

  status connect(SSL* id) {
    log("attempting connection");

    auto i = ::SSL_connect(id);

    return i <= 0 ?
      status::FAIL : status::OK;
  }
}
