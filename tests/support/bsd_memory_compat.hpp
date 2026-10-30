#pragma once
#ifdef _WIN32
#include <cstddef>
#include <cstring>
// The portable tests use macOS kernel headers which call the BSD memory APIs.
inline void bzero(void *dst, std::size_t length) { std::memset(dst, 0, length); }
inline void bcopy(const void *src, void *dst, std::size_t length) {
    std::memmove(dst, src, length);
}
#endif
