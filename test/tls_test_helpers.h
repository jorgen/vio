#pragma once

// Shared helpers for the TLS test suites: self-contained certificate generation
// (a CA + a leaf signed by it) and an ephemeral loopback TCP server. Uses only
// the OpenSSL X509/PEM API, so it works against any wired SSL backend.

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <cstdint>
#include <expected>
#include <string>
#include <utility>
#include <vector>

#include <vio/error.h>
#include <vio/event_loop.h>
#include <vio/operation/tcp.h>
#include <vio/operation/tcp_server.h>

namespace vio_test
{

struct cert_set_t
{
  std::vector<uint8_t> ca_cert; // PEM CA certificate (trust anchor)
  std::vector<uint8_t> cert;    // PEM leaf certificate (signed by the CA)
  std::vector<uint8_t> key;     // PEM leaf private key
};

inline std::vector<uint8_t> pem_from_cert(X509 *c)
{
  BIO *bio = BIO_new(BIO_s_mem());
  PEM_write_bio_X509(bio, c);
  std::vector<uint8_t> data(BIO_pending(bio));
  BIO_read(bio, data.data(), static_cast<int>(data.size()));
  BIO_free(bio);
  return data;
}

inline std::vector<uint8_t> pem_from_key(EVP_PKEY *k)
{
  BIO *bio = BIO_new(BIO_s_mem());
  PEM_write_bio_PrivateKey(bio, k, nullptr, nullptr, 0, nullptr, nullptr);
  std::vector<uint8_t> data(BIO_pending(bio));
  BIO_read(bio, data.data(), static_cast<int>(data.size()));
  BIO_free(bio);
  return data;
}

// EC P-256 keys: near-instant to generate (unlike RSA-2048, which is very slow
// in a debug-built libcrypto and would dominate the test run).
inline EVP_PKEY *make_key()
{
  EVP_PKEY *pkey = nullptr;
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
  EVP_PKEY_keygen_init(ctx);
  EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1);
  EVP_PKEY_keygen(ctx, &pkey);
  EVP_PKEY_CTX_free(ctx);
  return pkey;
}

// A self-contained CA plus a leaf certificate with the given common name, signed
// by that CA. Hostname verification relies on the CN (no SAN), which is what the
// vio TLS tests connect against.
inline cert_set_t make_cert_set(const std::string &cn)
{
  EVP_PKEY *ca_key = make_key();
  X509 *ca = X509_new();
  X509_set_version(ca, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(ca), 1);
  X509_gmtime_adj(X509_get_notBefore(ca), 0);
  X509_gmtime_adj(X509_get_notAfter(ca), 31536000L);
  X509_set_pubkey(ca, ca_key);
  auto *ca_name = X509_get_subject_name(ca);
  const std::string ca_cn = cn + " CA";
  X509_NAME_add_entry_by_txt(ca_name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>(ca_cn.c_str()), -1, -1, 0);
  X509_set_issuer_name(ca, ca_name);
  X509_sign(ca, ca_key, EVP_sha256());

  EVP_PKEY *leaf_key = make_key();
  X509 *leaf = X509_new();
  X509_set_version(leaf, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(leaf), 2);
  X509_gmtime_adj(X509_get_notBefore(leaf), 0);
  X509_gmtime_adj(X509_get_notAfter(leaf), 31536000L);
  X509_set_pubkey(leaf, leaf_key);
  auto *leaf_name = X509_get_subject_name(leaf);
  X509_NAME_add_entry_by_txt(leaf_name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>(cn.c_str()), -1, -1, 0);
  X509_set_issuer_name(leaf, ca_name);
  X509_sign(leaf, ca_key, EVP_sha256());

  cert_set_t out{.ca_cert = pem_from_cert(ca), .cert = pem_from_cert(leaf), .key = pem_from_key(leaf_key)};
  X509_free(ca);
  EVP_PKEY_free(ca_key);
  X509_free(leaf);
  EVP_PKEY_free(leaf_key);
  return out;
}

inline std::expected<std::pair<vio::tcp_server_t, int>, vio::error_t> get_ephemeral_port(vio::event_loop_t &event_loop)
{
  auto addr = vio::ip4_addr("127.0.0.1", 0);
  if (!addr.has_value())
    return std::unexpected(addr.error());
  auto tcp_server = vio::tcp_create_server(event_loop);
  if (!tcp_server.has_value())
    return std::unexpected(tcp_server.error());
  auto bind_res = vio::tcp_bind(tcp_server.value(), reinterpret_cast<const sockaddr *>(&addr.value()));
  if (!bind_res.has_value())
    return std::unexpected(bind_res.error());
  auto sockname_result = vio::sockname(tcp_server->tcp);
  if (!sockname_result.has_value())
    return std::unexpected(sockname_result.error());
  sockaddr_storage sa_storage = sockname_result.value();
  const auto *sa_in = reinterpret_cast<sockaddr_in *>(&sa_storage);
  return std::make_pair(std::move(tcp_server.value()), static_cast<int>(ntohs(sa_in->sin_port)));
}

} // namespace vio_test
