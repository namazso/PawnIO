#pragma once

#if defined(_M_AMD64) || defined(__amd64__)
#define ARCH_X64 1
#define ARCH 1
#elif defined(_M_ARM64) || defined(__aarch64__)
#define ARCH_A64 1
#define ARCH 2
#else
#error "Unsupported architecture"
#endif
