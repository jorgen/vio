#include <doctest/doctest.h>

#include <vio/ssl_config_t.h>

TEST_SUITE("ssl_config_t")
{
  // verify_depth is forwarded to tls_config_set_verify_depth(cfg, int). Real CA
  // chains need depths of 2-9; if the field can only hold a bool, any configured
  // depth silently collapses to 1.
  TEST_CASE("verify_depth preserves a chain depth greater than 1")
  {
    vio::ssl_config_t cfg;
    cfg.verify_depth = 4;
    REQUIRE(cfg.verify_depth.has_value());
    CHECK_EQ(*cfg.verify_depth, 4);
  }
}
