#pragma once

#define REQUIRE_EXPECTED(x) REQUIRE_MESSAGE(x.has_value(), x.error().msg)
