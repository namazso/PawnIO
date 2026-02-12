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

#include <Windows.h>

#include <wincrypt.h>
#include <winternl.h>

#include <vector>

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "ntdll.lib")

#define SHA256_LEN (32)

static NTSTATUS calculate_sha256(const void* data, size_t size, uint8_t* sha256) {
  BCRYPT_ALG_HANDLE alg_handle{};
  auto status = BCryptOpenAlgorithmProvider(
    &alg_handle,
    BCRYPT_SHA256_ALGORITHM,
    nullptr,
    0
  );

  if (NT_SUCCESS(status)) {
    ULONG len = 0, rlen = 0;
    status = BCryptGetProperty(
      alg_handle,
      BCRYPT_OBJECT_LENGTH,
      (PUCHAR)&len,
      sizeof(len),
      &rlen,
      0
    );

    if (NT_SUCCESS(status) && rlen == sizeof(len)) {
      const auto hash_obj = _alloca(len);

      BCRYPT_HASH_HANDLE hash_handle{};
      status = BCryptCreateHash(
        alg_handle,
        &hash_handle,
        (PUCHAR)hash_obj,
        len,
        nullptr,
        0,
        0
      );

      if (NT_SUCCESS(status)) {
        status = BCryptHashData(
          hash_handle,
          (PUCHAR) const_cast<void*>(data),
          (ULONG)size,
          0
        );

        if (NT_SUCCESS(status)) {
          status = BCryptFinishHash(hash_handle, sha256, SHA256_LEN, 0);
        }

        BCryptDestroyHash(hash_handle);
      }
    }

    BCryptCloseAlgorithmProvider(alg_handle, 0);
  }

  return status;
}

/*static DWORD pem_to_blob_public(const char* pem, LPCSTR blob_type, std::vector<uint8_t>& out) {
  DWORD ret = ERROR_SUCCESS;
  out.clear();
  DWORD der_len{};
  auto succeeded = CryptStringToBinaryA(
    pem,
    (DWORD)strlen(pem),
    CRYPT_STRING_BASE64HEADER,
    nullptr,
    &der_len,
    nullptr,
    nullptr
  );
  if (succeeded) {
    std::vector<uint8_t> der;
    der.resize(der_len);
    succeeded = CryptStringToBinaryA(
      pem,
      (DWORD)strlen(pem),
      CRYPT_STRING_BASE64HEADER,
      der.data(),
      &der_len,
      nullptr,
      nullptr
    );
    if (succeeded) {
      CRYPT_DECODE_PARA para;
      para.cbSize = sizeof(para);
      para.pfnAlloc = +[](size_t sz) { return malloc(sz); };
      para.pfnFree = +[](void* p) { return free(p); };

      CERT_PUBLIC_KEY_INFO* x509{};
      DWORD x509_len{};
      succeeded = CryptDecodeObjectEx(
        X509_ASN_ENCODING,
        X509_PUBLIC_KEY_INFO,
        der.data(),
        (DWORD)der.size(),
        CRYPT_DECODE_ALLOC_FLAG,
        &para,
        &x509,
        &x509_len
      );
      if (succeeded) {
        uint8_t* key{};
        DWORD key_len{};
        succeeded = CryptDecodeObjectEx(
          X509_ASN_ENCODING,
          blob_type,
          x509->PublicKey.pbData,
          x509->PublicKey.cbData,
          CRYPT_DECODE_ALLOC_FLAG,
          &para,
          &key,
          &key_len
        );

        if (succeeded) {
          out.resize(key_len);
          memcpy(out.data(), key, key_len);

          free(key);
        } else {
          ret = GetLastError();
        }

        free(x509);
      } else {
        ret = GetLastError();
      }
    } else {
      ret = GetLastError();
    }
  } else {
    ret = GetLastError();
  }
  return ret;
}*/

static DWORD pem_to_blob_private(const char* pem, LPCSTR blob_type, std::vector<uint8_t>& out) {
  DWORD ret = ERROR_SUCCESS;
  out.clear();
  DWORD der_len{};
  auto succeeded = CryptStringToBinaryA(
    pem,
    (DWORD)strlen(pem),
    CRYPT_STRING_BASE64HEADER,
    nullptr,
    &der_len,
    nullptr,
    nullptr
  );
  if (succeeded) {
    std::vector<uint8_t> der;
    der.resize(der_len);
    succeeded = CryptStringToBinaryA(
      pem,
      (DWORD)strlen(pem),
      CRYPT_STRING_BASE64HEADER,
      der.data(),
      &der_len,
      nullptr,
      nullptr
    );
    if (succeeded) {
      CRYPT_DECODE_PARA para;
      para.cbSize = sizeof(para);
      para.pfnAlloc = +[](size_t sz) { return malloc(sz); };
      para.pfnFree = +[](void* p) { return free(p); };

      CRYPT_PRIVATE_KEY_INFO* x509{};
      DWORD x509_len{};
      succeeded = CryptDecodeObjectEx(
        X509_ASN_ENCODING,
        PKCS_PRIVATE_KEY_INFO,
        der.data(),
        (DWORD)der.size(),
        CRYPT_DECODE_ALLOC_FLAG,
        &para,
        &x509,
        &x509_len
      );
      if (succeeded) {
        uint8_t* key{};
        DWORD key_len{};
        succeeded = CryptDecodeObjectEx(
          X509_ASN_ENCODING,
          blob_type,
          x509->PrivateKey.pbData,
          x509->PrivateKey.cbData,
          CRYPT_DECODE_ALLOC_FLAG,
          &para,
          &key,
          &key_len
        );

        if (succeeded) {
          out.resize(key_len);
          memcpy(out.data(), key, key_len);

          free(key);
        } else {
          ret = GetLastError();
        }

        free(x509);
      } else {
        ret = GetLastError();
      }
    } else {
      ret = GetLastError();
    }
  } else {
    ret = GetLastError();
  }
  return ret;
}

DWORD sign(const char* pem, const uint8_t* data, size_t len, std::vector<uint8_t>& signature) {
  signature.clear();
  uint8_t sha256[SHA256_LEN];
  auto status = calculate_sha256(data, len, sha256);
  if (!NT_SUCCESS(status))
    return RtlNtStatusToDosError(status);
  std::vector<uint8_t> key;
  const auto ret = pem_to_blob_private(pem, CNG_RSA_PRIVATE_KEY_BLOB, key);
  if (ret)
    return ret;

  BCRYPT_ALG_HANDLE alg_handle{};
  status = BCryptOpenAlgorithmProvider(
    &alg_handle,
    BCRYPT_RSA_ALGORITHM,
    nullptr,
    0
  );

  if (NT_SUCCESS(status)) {
    BCRYPT_KEY_HANDLE key_handle{};

    status = BCryptImportKeyPair(
      alg_handle,
      nullptr,
      BCRYPT_RSAPRIVATE_BLOB,
      &key_handle,
      key.data(),
      (ULONG)key.size(),
      0
    );


    if (NT_SUCCESS(status)) {
      BCRYPT_PKCS1_PADDING_INFO padding;
      padding.pszAlgId = BCRYPT_SHA256_ALGORITHM;

      ULONG signature_len{};

      BCryptSignHash(
        key_handle,
        &padding,
        sha256,
        SHA256_LEN,
        nullptr,
        0,
        &signature_len,
        BCRYPT_PAD_PKCS1
      );

      signature.resize(signature_len);

      status = BCryptSignHash(
        key_handle,
        &padding,
        sha256,
        SHA256_LEN,
        signature.data(),
        (ULONG)signature.size(),
        &signature_len,
        BCRYPT_PAD_PKCS1
      );

      if (!NT_SUCCESS(status))
        signature.clear();

      BCryptDestroyKey(key_handle);
    }

    BCryptCloseAlgorithmProvider(alg_handle, 0);
  }

  return RtlNtStatusToDosError(status);
}
