#if !defined(VIO_DOCTEST_IN_LIBRARY)
#define DOCTEST_CONFIG_IMPLEMENT
#endif
#include <doctest/doctest.h>

int main(int argc, char** argv) {
    doctest::Context context;
    context.applyCommandLine(argc, argv);
    return context.run();
}