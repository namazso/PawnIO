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

#pragma once

#define PAWNIO_PUBLICAPI EXTERN_C __declspec(dllexport)

/// Returns the current version of PawnIO.
/// 
/// @return Version in ((major << 16) | (minor << 8) | patch) format.
PAWNIO_PUBLICAPI ULONG pawnio_version();

/// Structure that holds a trusted public key and its length.
struct trusted_pubkey {
  /// Pointer to the raw public key data.
  PCUCHAR data;
  /// Length of the public key data in bytes.
  ULONG_PTR len;
};

/// Returns an array of trusted public keys.
/// 
/// @return Pointer to an array of trusted_pubkey structures. The array is
///         terminated by an entry with NULL data.
PAWNIO_PUBLICAPI const struct trusted_pubkey* pawnio_trusted_keys();

/// Callback function type that gets called when a VM is created.
/// 
/// @param ctx Context pointer to the created VM.
/// @return Status code indicating whether to block or allow the creation.
typedef NTSTATUS pawnio_vm_callback_created(PVOID ctx);
typedef pawnio_vm_callback_created* ppawnio_vm_callback_created;

/// Registers a callback that will be called when a VM is created.
/// 
/// @param callback Pointer to the callback function.
/// @return Cookie that can be used to unregister the callback.
PAWNIO_PUBLICAPI PVOID pawnio_register_vm_callback_created(ppawnio_vm_callback_created callback);

/// Unregisters a previously registered VM creation callback.
/// 
/// @param cookie returned by pawnio_register_vm_callback_created.
PAWNIO_PUBLICAPI void pawnio_unregister_vm_callback_created(PVOID cookie);

/// Callback function type that gets called before a VM function is executed.
/// 
/// @param ctx Context pointer to the VM.
/// @param cip Code instruction pointer/function address to be executed.
/// @return Status code indicating whether to block or allow the execution.
typedef NTSTATUS pawnio_vm_callback_precall(PVOID ctx, UINT_PTR cip);
typedef pawnio_vm_callback_precall* ppawnio_vm_callback_precall;

/// Registers a callback that will be called before a VM function is executed.
/// 
/// @param callback Pointer to the callback function.
/// @return Cookie that can be used to unregister the callback.
PAWNIO_PUBLICAPI PVOID pawnio_register_vm_callback_precall(ppawnio_vm_callback_precall callback);

/// Unregisters a previously registered pre-call callback.
/// 
/// @param cookie Cookie returned by pawnio_register_vm_callback_precall.
PAWNIO_PUBLICAPI void pawnio_unregister_vm_callback_precall(PVOID cookie);

/// Callback function type that gets called after a VM function is executed.
/// 
/// @param ctx Context pointer to the VM.
typedef void pawnio_vm_callback_postcall(PVOID ctx);
typedef pawnio_vm_callback_postcall* ppawnio_vm_callback_postcall;

/// Registers a callback that will be called after a VM function is executed.
/// 
/// @param callback Pointer to the callback function.
/// @return Cookie that can be used to unregister the callback.
PAWNIO_PUBLICAPI PVOID pawnio_register_vm_callback_postcall(ppawnio_vm_callback_postcall callback);

/// Unregisters a previously registered post-call callback.
/// 
/// @param cookie Cookie returned by pawnio_register_vm_callback_postcall.
PAWNIO_PUBLICAPI void pawnio_unregister_vm_callback_postcall(PVOID cookie);

/// Callback function type that gets called when a VM is destroyed.
/// 
/// @param ctx Context pointer to the VM being destroyed.
typedef void pawnio_vm_callback_destroyed(PVOID ctx);
typedef pawnio_vm_callback_destroyed* ppawnio_vm_callback_destroyed;

/// Registers a callback that will be called when a VM is destroyed.
/// 
/// @param callback Pointer to the callback function.
/// @return Cookie that can be used to unregister the callback.
PAWNIO_PUBLICAPI PVOID pawnio_register_vm_callback_destroyed(ppawnio_vm_callback_destroyed callback);

/// Unregisters a previously registered VM destruction callback.
/// 
/// @param cookie Cookie returned by pawnio_register_vm_callback_destroyed.
PAWNIO_PUBLICAPI void pawnio_unregister_vm_callback_destroyed(PVOID cookie);
