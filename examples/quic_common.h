#pragma once

// What every QUIC example in this directory needs before it can say anything
// about QUIC, and what vio does not offer a public API for.
//
// A QUIC server cannot exist without a certificate: unlike TCP, there is no
// unencrypted mode to demonstrate first. vio has no certificate-generation
// API, so the identity below is built with the raw OpenSSL X509 calls. It
// lives here rather than in each example because forty lines of X509
// boilerplate at the top of a QUIC example teaches nothing about QUIC.
//
// What is deliberately NOT here is the transport parameters, because they no
// longer need to be anywhere: connection_config_t initialises them from
// default_transport_parameters(), so an endpoint configured with nothing
// grants a working amount of credit. The two examples that still name a
// parameter start from that function and change the one field they are about,
// which is the shape any application should copy.
//
// The include order is load-bearing and is also the reason to include this
// header rather than the pieces. On Windows, wincrypt.h -- which arrives via
// any vio header -- defines X509_NAME as a macro, so an openssl
// header included first has its declarations shredded by it. vio/ssl_backend.h
// undoes those macros, so it must come after the vio headers and before
// openssl. Getting it wrong produces "undeclared identifier 'name'".

#include <vio/cancellation.h>
#include <vio/operation/quic_stream.h>
#include <vio/operation/sleep.h>
// For ip4_addr, which every example needs and which lives with the TCP
// operations because that is where it was first wanted.
#include <vio/operation/tcp.h>
#include <vio/run.h>

#include <vio/ssl_backend.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace vio_example
{

// A server's certificate and the key that goes with it, both PEM, which is
// what vio::quic::tls_config_t takes.
struct identity_t
{
  std::vector<std::uint8_t> certificate_pem;
  std::vector<std::uint8_t> private_key_pem;
};

inline std::vector<std::uint8_t> read_bio(BIO *bio)
{
  std::vector<std::uint8_t> out(static_cast<std::size_t>(BIO_pending(bio)));
  if (!out.empty())
  {
    BIO_read(bio, out.data(), static_cast<int>(out.size()));
  }
  return out;
}

// A certificate that is its own issuer, so a client can be handed the same PEM
// as its only trust anchor and verification succeeds without anything else
// existing. CA:TRUE is what makes that work; the subjectAltName is what makes
// the name check pass, since a certificate with only a common name is not
// matched by a modern verifier.
//
// P-256 rather than RSA because the key is generated every run and an RSA-2048
// keygen is long enough to be noticeable in a program that otherwise finishes
// in a fraction of a second.
inline identity_t make_self_signed(const char *common_name)
{
  EVP_PKEY *key = nullptr;
  EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
  EVP_PKEY_keygen_init(context);
  EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context, NID_X9_62_prime256v1);
  EVP_PKEY_keygen(context, &key);
  EVP_PKEY_CTX_free(context);

  X509 *certificate = X509_new();
  X509_set_version(certificate, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1);
  X509_gmtime_adj(X509_getm_notBefore(certificate), 0);
  X509_gmtime_adj(X509_getm_notAfter(certificate), 31536000L);
  X509_set_pubkey(certificate, key);
  X509_NAME *subject = X509_get_subject_name(certificate);
  X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>(common_name), -1, -1, 0);
  X509_set_issuer_name(certificate, subject);
  const std::string alt_name = std::string("DNS:") + common_name;
  X509_EXTENSION *basic = X509V3_EXT_nconf_nid(nullptr, nullptr, NID_basic_constraints, "critical,CA:TRUE");
  X509_add_ext(certificate, basic, -1);
  X509_EXTENSION_free(basic);
  X509_EXTENSION *san = X509V3_EXT_nconf_nid(nullptr, nullptr, NID_subject_alt_name, alt_name.c_str());
  X509_add_ext(certificate, san, -1);
  X509_EXTENSION_free(san);
  X509_sign(certificate, key, EVP_sha256());

  BIO *certificate_bio = BIO_new(BIO_s_mem());
  BIO *key_bio = BIO_new(BIO_s_mem());
  PEM_write_bio_X509(certificate_bio, certificate);
  PEM_write_bio_PrivateKey(key_bio, key, nullptr, nullptr, 0, nullptr, nullptr);
  identity_t out{.certificate_pem = read_bio(certificate_bio), .private_key_pem = read_bio(key_bio)};
  BIO_free(certificate_bio);
  BIO_free(key_bio);
  X509_free(certificate);
  EVP_PKEY_free(key);
  return out;
}

// A certificate authority: self-signed, marked as a CA, and kept so that it
// can sign others. A mesh needs one of these rather than a pile of pinned
// certificates -- pinning each peer in every other peer works for two nodes
// and stops at three, whereas one signature per new node changes nothing that
// already exists.
//
// The private key comes back with it because signing is the whole point.
inline identity_t make_certificate_authority(const char *common_name)
{
  return make_self_signed(common_name);
}

// A leaf identity signed by the authority above. The name goes in the subject,
// which is what the peer reads back from peer_certificate_subject() once the
// chain has verified, and so is what an application makes a decision on.
inline identity_t make_signed_by(const identity_t &authority, const char *common_name)
{
  EVP_PKEY *key = nullptr;
  EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
  EVP_PKEY_keygen_init(context);
  EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context, NID_X9_62_prime256v1);
  EVP_PKEY_keygen(context, &key);
  EVP_PKEY_CTX_free(context);

  // The authority is handed back as PEM, so it has to be read in again to sign
  // with. That is the same shape a real deployment has, where the CA is a file
  // rather than a variable.
  BIO *ca_certificate_bio = BIO_new_mem_buf(authority.certificate_pem.data(), static_cast<int>(authority.certificate_pem.size()));
  X509 *ca_certificate = PEM_read_bio_X509(ca_certificate_bio, nullptr, nullptr, nullptr);
  BIO_free(ca_certificate_bio);
  BIO *ca_key_bio = BIO_new_mem_buf(authority.private_key_pem.data(), static_cast<int>(authority.private_key_pem.size()));
  EVP_PKEY *ca_key = PEM_read_bio_PrivateKey(ca_key_bio, nullptr, nullptr, nullptr);
  BIO_free(ca_key_bio);

  X509 *certificate = X509_new();
  X509_set_version(certificate, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(certificate), 2);
  X509_gmtime_adj(X509_getm_notBefore(certificate), 0);
  X509_gmtime_adj(X509_getm_notAfter(certificate), 31536000L);
  X509_set_pubkey(certificate, key);
  X509_NAME *subject = X509_get_subject_name(certificate);
  X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>(common_name), -1, -1, 0);
  // Issued by the authority, which is what makes one signature enough for a
  // peer that has never seen this certificate before.
  X509_set_issuer_name(certificate, X509_get_subject_name(ca_certificate));
  const std::string alt_name = std::string("DNS:") + common_name;
  X509_EXTENSION *san = X509V3_EXT_nconf_nid(nullptr, nullptr, NID_subject_alt_name, alt_name.c_str());
  X509_add_ext(certificate, san, -1);
  X509_EXTENSION_free(san);
  X509_sign(certificate, ca_key, EVP_sha256());

  BIO *certificate_bio = BIO_new(BIO_s_mem());
  BIO *key_bio = BIO_new(BIO_s_mem());
  PEM_write_bio_X509(certificate_bio, certificate);
  PEM_write_bio_PrivateKey(key_bio, key, nullptr, nullptr, 0, nullptr, nullptr);
  identity_t out{.certificate_pem = read_bio(certificate_bio), .private_key_pem = read_bio(key_bio)};
  BIO_free(certificate_bio);
  BIO_free(key_bio);
  X509_free(certificate);
  EVP_PKEY_free(key);
  X509_free(ca_certificate);
  EVP_PKEY_free(ca_key);
  return out;
}

// The stream API takes and returns bytes, and everything an example wants to
// send is text, so this conversion appears in every one of them.
inline std::span<const std::uint8_t> bytes_of(std::string_view text)
{
  return {reinterpret_cast<const std::uint8_t *>(text.data()), text.size()};
}

inline std::string text_of(std::span<const std::uint8_t> bytes)
{
  return {reinterpret_cast<const char *>(bytes.data()), bytes.size()};
}

// The same, for what a stream reader hands back. It owns its buffer, so the
// text has to be copied out of it before the buffer goes.
inline std::string text_of(const vio::unique_buf_t &buffer)
{
  return {buffer.chars(), buffer.size()};
}

} // namespace vio_example
