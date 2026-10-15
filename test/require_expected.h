#pragma once

#include <string>

#define REQUIRE_EXPECTED(x) REQUIRE_MESSAGE(x.has_value(), (x.has_value() ? std::string() : x.error().msg))
