// PawnIOLib - Library and tooling source to be used with PawnIO.
// Copyright (C) 2026  namazso <admin@namazso.eu>
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

#include <windows.h>

#include <PawnIOLib.h>

#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <bit>

DWORD sign(const char* pem, const uint8_t* data, size_t len, std::vector<uint8_t>& signature);

static void printusage(const char* name) {
  auto slash = strrchr(name, '/');
  slash = slash == nullptr ? name : slash + 1;
  auto bkslash = strrchr(name, '\\');
  bkslash = bkslash == nullptr ? name : bkslash + 1;
  const auto last = (std::max)(slash, bkslash);
  fprintf(stderr, "Usage:\n\n");
  fprintf(stderr, "%s sign <amx> <output> [keyfile]\n", last);
  fprintf(stderr, "%s test <amx> [keyfile]\n", last);
  fprintf(stderr, "%s interactive <amx> [keyfile]\n", last);
  exit(1);
}

static std::vector<uint8_t> read_all(const char* path) {
  std::ifstream is(path, std::ios::binary);
  if (!is.good() || !is.is_open())
    return {};
  is.seekg(0, std::ifstream::end);
  std::vector<uint8_t> data;
  data.resize((size_t)is.tellg());
  is.seekg(0, std::ifstream::beg);
  is.read(reinterpret_cast<char*>(data.data()), (std::streamsize)data.size());
  return data;
}

static bool write_all(const char* path, const void* data, size_t size) {
  std::ofstream os(path, std::ios::out | std::ios::binary);
  if (!os.good() || !os.is_open())
    return false;
  os.write((const char*)data, (std::streamsize)size);
  return os.good();
}

static std::vector<uint8_t> get_as_blob(const char* maybe_amx, const char* key) {
  auto input = read_all(maybe_amx);
  if (input.empty()) {
    fprintf(stderr, "AMX input unreadable or empty\n");
    exit(1);
  }

  std::string pem;
  if (key) {
    std::vector<uint8_t> pem_bytes;
    pem_bytes = read_all(key);
    if (pem_bytes.empty()) {
      fprintf(stderr, "key input unreadable or empty\n");
      exit(1);
    }
    pem_bytes.push_back(0);
    pem = std::string{(char*)pem_bytes.data()};
  }

  if (input.size() < 6) {
    fprintf(stderr, "AMX input corrupt\n");
    exit(1);
  }

  std::vector<uint8_t> signature{};
  if (input[4] != 0xE1 || input[5] != 0xF1) {
    const auto sigsize = (uint32_t)input[0] | ((uint32_t)input[1] << 8) | ((uint32_t)input[2] << 16) | ((uint32_t)input[3] << 24);
    if (input.size() < sigsize + 4 + 6 || input[4 + sigsize + 4] != 0xE1 || input[4 + sigsize + 5] != 0xF1) {
      fprintf(stderr, "AMX input corrupt (maybe wrong cell size?)\n");
      exit(1);
    }
    signature = {input.begin() + 4 , input.begin() + 4 + sigsize};
    input = {input.begin() + 4 + sigsize, input.end()};
  }

  if (!pem.empty()) {
    signature = {};
    auto ret = sign(pem.c_str(), input.data(), input.size(), signature);
    if (ret != ERROR_SUCCESS) {
      fprintf(stderr, "signing failed: %lu\n", ret);
      exit((int)ret);
    }
  }
  std::vector<uint8_t> blob;
  blob.push_back(signature.size() & 0xff);
  blob.push_back((signature.size() >> 8) & 0xff);
  blob.push_back((signature.size() >> 16) & 0xff);
  blob.push_back((signature.size() >> 24) & 0xff);
  blob.insert(blob.end(), signature.begin(), signature.end());
  blob.insert(blob.end(), input.begin(), input.end());
  return blob;
}

int do_sign(const char* amx, const char* out, const char* key) {
  const auto blob = get_as_blob(amx, key);
  const auto ret = write_all(out, blob.data(), blob.size());
  if (!ret) {
    fprintf(stderr, "writing output failed\n");
    exit(1);
  }
  return 0;
}

int do_test(const char* amx, const char* key) {
  const auto blob = get_as_blob(amx, key);
  HANDLE h{};
  auto hr = pawnio_open(&h);
  if (!SUCCEEDED(hr)) {
    fprintf(stderr, "failed opening PawnIO device: %lx\n", hr);
    exit(1);
  }
  hr = pawnio_load(h, blob.data(), blob.size());
  if (!SUCCEEDED(hr)) {
    fprintf(stderr, "failed loading PawnIO module: %lx\n", hr);
    exit(1);
  }
  hr = pawnio_close(h);
  if (!SUCCEEDED(hr)) {
    fprintf(stderr, "failed closing PawnIO device: %lx\n", hr);
    exit(1);
  }
  return 0;
}

static char printable(char c) {
  return isprint(c) ? c : '.';
}

int do_interactive(const char* amx, const char* key) {
  const auto blob = get_as_blob(amx, key);
  HANDLE h{};
  auto hr = pawnio_open(&h);
  if (!SUCCEEDED(hr)) {
    fprintf(stderr, "failed opening PawnIO device: %lx\n", hr);
    exit(1);
  }
  hr = pawnio_load(h, blob.data(), blob.size());
  if (!SUCCEEDED(hr)) {
    fprintf(stderr, "failed loading PawnIO module: %lx\n", hr);
    exit(1);
  }
  _set_printf_count_output(true);
  printf("Entering interactive mode\n");
  while (true) {
    printf("> ");
    std::string str{};
    std::getline(std::cin, str);
    if (str == "quit")
      break;
    else {
      char name[32]{};
      size_t out_count{};
      size_t consumed{};
      sscanf_s(str.c_str(), "%s %zu %zn", name, (unsigned)std::size(name), &out_count, &consumed);
      auto ptr = str.c_str() + consumed;
      std::vector<uint64_t> in_buf{};
      uint64_t tmp{};
      while (sscanf_s(ptr, "%llx%zn", &tmp, &consumed) == 1) {
        in_buf.push_back(tmp);
        ptr += consumed;
      }
      std::vector<uint64_t> out_buf{};
      out_buf.resize(out_count);
      size_t ret_size{};
      hr = pawnio_execute(
        h,
        name,
        in_buf.data(),
        in_buf.size(),
        out_buf.data(),
        out_buf.size(),
        &ret_size
      );
      if (!SUCCEEDED(hr)) {
        printf("execute failed: %lx\n", hr);
      } else {
        printf("received %zu cells:\n", ret_size);
        out_buf.resize(ret_size);
        for (auto v : out_buf)
          printf(
            "%016llX %c%c%c%c%c%c%c%c %20lld %f (%f %f)\n",
            v,
            printable((char)((v >> 0) & 0xFF)),
            printable((char)((v >> 8) & 0xFF)),
            printable((char)((v >> 16) & 0xFF)),
            printable((char)((v >> 24) & 0xFF)),
            printable((char)((v >> 32) & 0xFF)),
            printable((char)((v >> 40) & 0xFF)),
            printable((char)((v >> 48) & 0xFF)),
            printable((char)((v >> 56) & 0xFF)),
            v,
            std::bit_cast<double>(v),
            std::bit_cast<float>((uint32_t)v),
            std::bit_cast<float>((uint32_t)(v >> 32))
          );
      }
    }
  }
  hr = pawnio_close(h);
  if (!SUCCEEDED(hr)) {
    fprintf(stderr, "failed closing PawnIO device: %lx\n", hr);
    exit(1);
  }
  return 0;
}

int main(int argc, char* argv[]) {
  if (argc < 2)
    printusage(argv[0]);

  if (0 == strcmp(argv[1], "sign")) {
    if (argc < 4)
      printusage(argv[0]);
    return do_sign(argv[2], argv[3], argc > 4 ? argv[4] : nullptr);
  } else if (0 == strcmp(argv[1], "test")) {
    if (argc < 3)
      printusage(argv[0]);
    return do_test(argv[2], argc > 3 ? argv[3] : nullptr);
  } else if (0 == strcmp(argv[1], "interactive")) {
    if (argc < 3)
      printusage(argv[0]);
    return do_interactive(argv[2], argc > 3 ? argv[3] : nullptr);
  } else {
    printusage(argv[0]);
  }
  return 0;
}
