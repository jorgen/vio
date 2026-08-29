#!/bin/bash
./build-asan/test/vio_tests > /tmp/out.txt 2>&1
EXIT_CODE=$?
echo "=== EXIT CODE: $EXIT_CODE ==="
echo "=== TOTAL LINES: $(wc -l < /tmp/out.txt) ==="
echo "=== FIRST 5 LINES ==="
head -5 /tmp/out.txt
echo "=== LAST 20 LINES ==="
tail -20 /tmp/out.txt
echo "=== DOCTEST/ASAN LINES ==="
grep -n "doctest\|SUMMARY\|leak\|Sanitizer\|test cases\|assertions\|Status:" /tmp/out.txt
