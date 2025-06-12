#include <doctest/doctest.h>

#include <string>
#include <vio/elastic_index_storage.h>

TEST_SUITE("elastic_index_storage_t Tests")
{
  TEST_CASE("Construction and initial state")
  {
    constexpr std::size_t preferredSize = 5;
    vio::elastic_index_storage_t<int, preferredSize> storage;

    // Check initial size
    CHECK_EQ(storage.size(), preferredSize);

    // Since none of them are yet used, they should be inactive
    for (std::size_t i = 0; i < preferredSize; ++i)
    {
      CHECK_FALSE(storage.is_active(i));
    }
  }

  TEST_CASE("Emplace single element")
  {
    vio::elastic_index_storage_t<int, 2> storage;
    auto index = storage.emplace(42);

    CHECK_EQ(storage.size(), 2);
    CHECK(storage.is_active(index));
    CHECK_EQ(storage[index], 42);

    // Now check currentItem
    CHECK_EQ(storage.current_item(), 42);
  }

  TEST_CASE("Emplace multiple elements and exceed preferred size")
  {
    vio::elastic_index_storage_t<int, 2> storage;
    auto idx1 = storage.emplace(10);
    auto idx2 = storage.emplace(20);

    // The next emplace should expand beyond the preferred size
    auto idx3 = storage.emplace(30);

    CHECK_EQ(storage.size(), 3);

    CHECK(storage.is_active(idx1));
    CHECK(storage.is_active(idx2));
    CHECK(storage.is_active(idx3));

    CHECK_EQ(storage[idx1], 10);
    CHECK_EQ(storage[idx2], 20);
    CHECK_EQ(storage[idx3], 30);
  }

  TEST_CASE("Deactivate element and resize behavior")
  {
    vio::elastic_index_storage_t<int, 3> storage;

    // Fill up to exactly the preferred size
    auto idxA = storage.emplace(100);
    auto idxB = storage.emplace(200);
    auto idxC = storage.emplace(300);
    CHECK_EQ(storage.size(), 3);

    // Deactivate one element and ensure it becomes inactive
    storage.deactivate(idxB);
    CHECK_FALSE(storage.is_active(idxB));

    // The storage should still report a size of at least 3
    CHECK_GE(storage.size(), static_cast<std::size_t>(3));

    // Reuse the deactivated slot:
    auto idxD = storage.emplace(400);
    CHECK(storage.is_active(idxD));
    CHECK_EQ(storage[idxD], 400);

    // Deactivate everything to trigger a potential shrink
    storage.deactivate(idxA);
    storage.deactivate(idxC);
    storage.deactivate(idxD);

    // In this implementation, the container will resize down to at least the preferred size
    CHECK_EQ(storage.size(), 3);
  }

  TEST_CASE("Iteration using next() and currentItem()")
  {
    vio::elastic_index_storage_t<int, 3> storage;

    // Emplace three items
    auto idx1 = storage.emplace(1);
    auto idx2 = storage.emplace(2);
    auto idx3 = storage.emplace(3);

    // currentItem should initially point to the first item inserted
    CHECK_EQ(storage.current_item(), 1);

    // Move to the next active item
    REQUIRE(storage.next());
    CHECK_EQ(storage.current_item(), 2);

    // Move to the next active item
    REQUIRE(storage.next());
    CHECK_EQ(storage.current_item(), 3);

    // No more active items to move to
    CHECK_FALSE(storage.next());

    // Deactivate the middle item
    storage.deactivate(idx2);

    // Reset and check that Next will skip the deactivated item
    // The container doesn't provide a built-in "reset" method,
    // so we'll just verify that continuing from the last position
    // tries to move beyond the last item:
    CHECK_FALSE(storage.next());
  }

  TEST_CASE("Iteration skips deactivated items")
  {
    vio::elastic_index_storage_t<int, 3> storage;

    auto idx1 = storage.emplace(10);
    auto idx2 = storage.emplace(20);
    auto idx3 = storage.emplace(30);

    // Deactivate the middle item before starting iteration
    storage.deactivate(idx2);

    // Check initial item
    CHECK_EQ(storage.current_item(), 10);

    // Next should skip idx2 and go directly to idx3
    REQUIRE(storage.next());
    CHECK_EQ(storage.current_item(), 30);

    // No more items after idx3
    CHECK_FALSE(storage.next());
  }

  TEST_CASE("Access operator[] for active/inactive items")
  {
    vio::elastic_index_storage_t<int, 4> storage;
    auto idx1 = storage.emplace(10);
    auto idx2 = storage.emplace(20);

    CHECK(storage.is_active(idx1));
    CHECK(storage.is_active(idx2));

    // Deactivate one item
    storage.deactivate(idx2);
    CHECK_FALSE(storage.is_active(idx2));

    // Confirm reading from an active index works
    CHECK_EQ(storage[idx1], 10);

    // We cannot safely check accessing an inactive index with operator[]
    // because it uses an assert. Instead, we rely on isActive checks.
    // In a debug build, it would trigger an assertion failure to do:
    // auto val = storage[idx2];
    // So we simply confirm isActive returns false for it.
  }

  TEST_CASE("Emplace with different types (brief check)")
  {
    // This is just a small check to ensure it compiles and works with different types
    vio::elastic_index_storage_t<std::string, 2> stringStorage;
    auto idxStr = stringStorage.emplace("Hello");
    CHECK(stringStorage.is_active(idxStr));
    CHECK_EQ(stringStorage[idxStr], "Hello");

    // For a user-defined type, using a pair as a simple example
    vio::elastic_index_storage_t<std::pair<int, double>, 1> pairStorage;
    auto idxPair = pairStorage.emplace(std::make_pair(5, 3.14));
    CHECK(pairStorage.is_active(idxPair));
    CHECK_EQ(pairStorage[idxPair].first, 5);
    CHECK_EQ(pairStorage[idxPair].second, doctest::Approx(3.14));
  }
}