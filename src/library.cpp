/*
  Copyright (c) 2025 Jørgen Lind

  Permission is hereby granted, free of charge, to any person obtaining a copy of
  this software and associated documentation files (the "Software"), to deal in
  the Software without restriction, including without limitation the rights to
  use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
  of the Software, and to permit persons to whom the Software is furnished to do
  so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*/

#include "vio/event_loop.h"
#include "vio/operation/sleep.h"
#include "vio/operation/tls_common.h"
#include "vio/thread_pool.h"

#include <cmrc/cmrc.hpp>
#include <span>
#include <tls.h>

#ifdef _WIN32
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <string>
#include <wincrypt.h>
#include <windows.h>
#endif

CMRC_DECLARE(vio); // NOLINT(modernize-type-traits)
namespace vio
{
static std::string get_fallback_ca_certificates()
{
  auto file = cmrc::vio::get_filesystem().open("default_certs/cert.pem");
  if (file.size() == 0)
  {
    return {};
  }
  return {file.begin(), file.size()};
}

#ifdef _WIN32
static std::string convert_der_cert_to_pem(const unsigned char *der_data, size_t der_len)
{
  // Create a memory BIO to hold the DER certificate
  BIO *mem_bio = BIO_new_mem_buf(der_data, static_cast<int>(der_len));
  if (!mem_bio)
  {
    return {};
  }

  // Parse as X509
  X509 *x509 = d2i_X509_bio(mem_bio, nullptr);
  BIO_free(mem_bio);
  if (!x509)
    return {};

  // Create another memory BIO to write PEM data into
  BIO *pem_bio = BIO_new(BIO_s_mem());
  if (!pem_bio)
  {
    X509_free(x509);
    return {};
  }

  // Write X509 as PEM into pemBio
  if (!PEM_write_bio_X509(pem_bio, x509))
  {
    X509_free(x509);
    BIO_free(pem_bio);
    return {};
  }

  // Extract PEM data into a std::string
  char *pem_data = nullptr;
  long pem_len = BIO_get_mem_data(pem_bio, &pem_data);
  std::string pem_cert(pem_data, static_cast<size_t>(pem_len));

  // Clean up
  X509_free(x509);
  BIO_free(pem_bio);

  return pem_cert;
}

static std::string get_windows_root_ca_certificates()
{
  HCERTSTORE cert_store = CertOpenSystemStore(NULL, "ROOT");
  if (!cert_store)
  {
    return {};
  }
  // Collect PEM-encoded certs here
  std::string all_pem_certs;

  PCCERT_CONTEXT cert_ctx = nullptr;
  while ((cert_ctx = CertEnumCertificatesInStore(cert_store, cert_ctx)) != nullptr)
  {
    auto der_ptr = cert_ctx->pbCertEncoded;
    auto der_len = cert_ctx->cbCertEncoded;

    // Convert the DER chunk to PEM
    std::string pem_cert = convert_der_cert_to_pem(der_ptr, der_len);
    if (!pem_cert.empty())
    {
      all_pem_certs += pem_cert;
    }
  }
  // Cleanup
  CertCloseStore(cert_store, 0);
  return all_pem_certs;
}

static std::string resolve_windows_ca_certificates()
{
  auto cert = get_windows_root_ca_certificates();
  if (cert.empty())
  {
    return get_fallback_ca_certificates();
  }
  return cert;
}

std::string get_default_ca_certificates()
{
  static const std::string cert = resolve_windows_ca_certificates();
  return cert;
}

#else

std::string get_default_ca_certificates()
{
  static const std::string cert = get_fallback_ca_certificates();
  return cert;
}
#endif

} // namespace vio
