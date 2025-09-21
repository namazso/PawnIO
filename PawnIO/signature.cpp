// PawnIO - Input-output driver
// Copyright (C) 2023  namazso <admin@namazso.eu>
// 
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
// 
// Linking PawnIO statically or dynamically with other modules is making a
// combined work based on PawnIO. Thus, the terms and conditions of the GNU
// General Public License cover the whole combination.
// 
// In addition, as a special exception, the copyright holders of PawnIO give
// you permission to combine PawnIO program with free software programs or
// libraries that are released under the GNU LGPL and with independent modules
// that communicate with PawnIO solely through the device IO control
// interface. You may copy and distribute such a system following the terms of
// the GNU GPL for PawnIO and the licenses of the other code concerned,
// provided that you include the source code of that other code when and as
// the GNU GPL requires distribution of source code.
// 
// Note that this exception does not include programs that communicate with
// PawnIO over the Pawn interface. This means that all modules loaded into
// PawnIO must be compatible with this licence, including the earlier
// exception clause. We recommend using the GNU Lesser General Public License
// version 2.1 to fulfill this requirement.
// 
// For alternative licensing options, please contact the copyright holder at
// admin@namazso.eu.
// 
// Note that people who make modified versions of PawnIO are not obligated to
// grant this special exception for their modified versions; it is their
// choice whether to do so. The GNU General Public License gives permission
// to release a modified version without this exception; this exception also
// makes it possible to release a modified version which carries forward this
// exception.

#include "stdafx.h"

#include "signature.h"

NTSTATUS calculate_sha256(const void* data, size_t size, sha256_buf* sha256) {
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
          (PUCHAR)const_cast<void*>(data),
          (ULONG)size,
          0
        );

        if (NT_SUCCESS(status)) {
          status = BCryptFinishHash(hash_handle, sha256->data(), (ULONG)sha256->size(), 0);
        }

        BCryptDestroyHash(hash_handle);
      }
    }

    BCryptCloseAlgorithmProvider(alg_handle, 0);
  }

  return status;
}

NTSTATUS verify_sig(const sha256_buf& sha256, const uint8_t* sig, size_t sig_len, const uint8_t* pubkey, size_t pubkey_len) {
  if (pubkey_len < sizeof(BCRYPT_KEY_BLOB))
    return STATUS_INVALID_PARAMETER;

  BCRYPT_KEY_BLOB key_blob{};
  memcpy(&key_blob, pubkey, sizeof(key_blob));

  LPCWSTR alg_id{};
  LPCWSTR blob_type{};

  switch (key_blob.Magic) {
  case BCRYPT_RSAPUBLIC_MAGIC:
    alg_id = BCRYPT_RSA_ALGORITHM;
    blob_type = BCRYPT_RSAPUBLIC_BLOB;
    break;
  default:
    return STATUS_INVALID_PARAMETER;
  }

  BCRYPT_ALG_HANDLE alg_handle{};
  auto status = BCryptOpenAlgorithmProvider(
    &alg_handle,
    alg_id,
    nullptr,
    0
  );

  if (NT_SUCCESS(status)) {
    BCRYPT_KEY_HANDLE pubkey_handle{};

    status = BCryptImportKeyPair(
      alg_handle,
      nullptr,
      blob_type,
      &pubkey_handle,
      const_cast<PUCHAR>(pubkey),
      (ULONG)pubkey_len,
      0
    );


    if (NT_SUCCESS(status)) {
      BCRYPT_PKCS1_PADDING_INFO padding;
      padding.pszAlgId = BCRYPT_SHA256_ALGORITHM;

      status = BCryptVerifySignature(
        pubkey_handle,
        &padding,
        const_cast<PUCHAR>(sha256.data()),
        (ULONG)sha256.size(),
        const_cast<PUCHAR>(sig),
        (ULONG)sig_len,
        BCRYPT_PAD_PKCS1
      );

      BCryptDestroyKey(pubkey_handle);
    }

    BCryptCloseAlgorithmProvider(alg_handle, 0);
  }

  return status;
}
