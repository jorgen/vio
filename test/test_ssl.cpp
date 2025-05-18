#include <doctest/doctest.h>
#include <vio/event_loop.h>
#include <vio/event_pipe.h>
#include <vio/operation/ssl.h>
#include <vio/operation/tcp.h>
#include <vio/task.h>

#include "require_expected.h"

void hello()
{
  fprintf(stderr, "Hello\n");
}
