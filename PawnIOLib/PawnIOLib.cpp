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

#include <ntstatus.h>

#define WIN32_NO_STATUS

#include <windows.h>

#include <winternl.h>

#include <malloc.h>

#include <PawnIOLib.h>

#include <pawnio_um.h>

#undef RtlMoveMemory
EXTERN_C NTSYSAPI VOID NTAPI RtlMoveMemory(
  VOID UNALIGNED* Destination,
  CONST VOID UNALIGNED* Source,
  SIZE_T Length
);

typedef enum _EVENT_TYPE {
  NotificationEvent,
  SynchronizationEvent
} EVENT_TYPE;

EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtCreateEvent(
  _Out_ PHANDLE EventHandle,
  _In_ ACCESS_MASK DesiredAccess,
  _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
  _In_ EVENT_TYPE EventType,
  _In_ BOOLEAN InitialState
);

static NTSTATUS synchronous_ioctl(
  _In_ HANDLE FileHandle,
  _In_ ULONG IoControlCode,
  _In_opt_ PVOID InputBuffer,
  _In_ ULONG InputBufferLength,
  _Out_opt_ PVOID OutputBuffer,
  _In_ ULONG OutputBufferLength,
  _Out_opt_ PSIZE_T OutputWritten
) {
  HANDLE event = nullptr;

  // Create an event for synchronization
  NTSTATUS status = NtCreateEvent(
    &event,
    EVENT_ALL_ACCESS,
    nullptr,
    NotificationEvent,
    FALSE
  );

  if (!NT_SUCCESS(status))
    return status;

  IO_STATUS_BLOCK iosb{};

  // Call the IoControl function with our event
  status = NtDeviceIoControlFile(
    FileHandle,
    event,
    nullptr,
    nullptr,
    &iosb,
    IoControlCode,
    InputBuffer,
    InputBufferLength,
    OutputBuffer,
    OutputBufferLength
  );

  // If the operation is pending, wait for completion
  if (status == STATUS_PENDING) {
    status = NtWaitForSingleObject(event, FALSE, nullptr);
    if (NT_SUCCESS(status)) {
      // Get the actual result from the IO status block
      status = iosb.Status;
    }
  }

  if (OutputWritten && NT_SUCCESS(status)) {
    *OutputWritten = iosb.Information;
  }

  // Clean up
  NtClose(event);
  return status;
}

static HRESULT nt_to_hresult(NTSTATUS status) {
  return HRESULT_FROM_WIN32(RtlNtStatusToDosError(status));
}

static BOOL nt_to_win32(NTSTATUS status) {
  if (!NT_SUCCESS(status)) {
    SetLastError(RtlNtStatusToDosError(status));
    return FALSE;
  }
  return TRUE;
}

PAWNIOAPI pawnio_version(PULONG version) {
  return nt_to_hresult(pawnio_version_nt(version));
}

PAWNIOWINAPI pawnio_version_win32(PULONG version) {
  return nt_to_win32(pawnio_version_nt(version));
}

PAWNIONTAPI pawnio_version_nt(PULONG version) {
  *version = 0x00020000; // 2.0.0
  return STATUS_SUCCESS;
}

PAWNIOAPI pawnio_open(PHANDLE handle) {
  return nt_to_hresult(pawnio_open_nt(handle));
}

PAWNIOWINAPI pawnio_open_win32(PHANDLE handle) {
  return nt_to_win32(pawnio_open_nt(handle));
}

PAWNIONTAPI pawnio_open_nt(PHANDLE handle) {
  *handle = nullptr;
  UNICODE_STRING ustr{};
  RtlInitUnicodeString(&ustr, k_device_path);
  OBJECT_ATTRIBUTES attr{};
  attr.Length = sizeof(attr);
  attr.ObjectName = &ustr;
  IO_STATUS_BLOCK iosb{};
  return NtOpenFile(
    handle,
    GENERIC_READ | GENERIC_WRITE,
    &attr,
    &iosb,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    0
  );
}

PAWNIOAPI pawnio_load(HANDLE handle, const UCHAR* blob, SIZE_T size) {
  return nt_to_hresult(pawnio_load_nt(handle, blob, size));
}

PAWNIOWINAPI pawnio_load_win32(HANDLE handle, const UCHAR* blob, SIZE_T size) {
  return nt_to_win32(pawnio_load_nt(handle, blob, size));
}

PAWNIONTAPI pawnio_load_nt(HANDLE handle, const UCHAR* blob, SIZE_T size) {
  return synchronous_ioctl(
    handle,
    IOCTL_PIO_LOAD_BINARY,
    (PVOID)blob,
    (ULONG)size,
    nullptr,
    0,
    nullptr
  );
}

PAWNIOAPI pawnio_execute(
  HANDLE handle,
  PCSTR name,
  const ULONG64* in,
  SIZE_T in_size,
  PULONG64 out,
  SIZE_T out_size,
  PSIZE_T return_size
) {
  return nt_to_hresult(pawnio_execute_nt(handle, name, in, in_size, out, out_size, return_size));
}

PAWNIOWINAPI pawnio_execute_win32(
  HANDLE handle,
  PCSTR name,
  const ULONG64* in,
  SIZE_T in_size,
  PULONG64 out,
  SIZE_T out_size,
  PSIZE_T return_size
) {
  return nt_to_win32(pawnio_execute_nt(handle, name, in, in_size, out, out_size, return_size));
}

static constexpr auto FN_NAME_LENGTH = 32u;

PAWNIONTAPI pawnio_execute_nt(
  HANDLE handle,
  PCSTR name,
  const ULONG64* in,
  SIZE_T in_size,
  PULONG64 out,
  SIZE_T out_size,
  PSIZE_T return_size
) {
  *return_size = 0;
  char* p = nullptr;
  HANDLE heap = nullptr;
  void* heapalloc = nullptr;
  const auto allocsize = in_size * sizeof(*in) + FN_NAME_LENGTH;
  if (allocsize > 512) {
    heap = GetProcessHeap();
    heapalloc = HeapAlloc(heap, 0, allocsize);
    p = (char*)heapalloc;
    if (!p)
      return STATUS_NO_MEMORY;
  } else {
    p = (char*)_alloca(allocsize);
  }
  lstrcpynA(p, name, 31);
  p[31] = 0;
  if (in_size)
    RtlMoveMemory(p + 32, in, in_size * sizeof(*in));

  SIZE_T written = 0;
  const auto status = synchronous_ioctl(
    handle,
    IOCTL_PIO_EXECUTE_FN,
    p,
    (ULONG)allocsize,
    out,
    (ULONG)out_size * sizeof(*out),
    &written
  );
  if (NT_SUCCESS(status)) {
    *return_size = written / sizeof(*out);
  }
  if (heapalloc)
    HeapFree(heap, 0, p);
  return status;
}

PAWNIOAPI pawnio_execute_async(
  HANDLE handle,
  PCSTR name,
  const ULONG64* in,
  SIZE_T in_size,
  PULONG64 out,
  SIZE_T out_size,
  LPOVERLAPPED overlapped
) {
  // Partial recreation of Windows' own DeviceIoControl function

  overlapped->Internal = (ULONG)STATUS_PENDING;

  const auto status = pawnio_execute_async_nt(
    handle,
    name,
    overlapped->hEvent,
    nullptr,
    (ULONG_PTR)overlapped->hEvent & 1 ? nullptr : overlapped,
    &overlapped->Internal,
    in,
    in_size,
    out,
    out_size
  );

  if (NT_SUCCESS(status) && status != STATUS_PENDING) {
    return S_OK;
  }

  return nt_to_hresult(status);
}

PAWNIOWINAPI pawnio_execute_async_win32(
  HANDLE handle,
  PCSTR name,
  const ULONG64* in,
  SIZE_T in_size,
  PULONG64 out,
  SIZE_T out_size,
  LPOVERLAPPED overlapped
  ) {
  // Partial recreation of Windows' own DeviceIoControl function

  overlapped->Internal = (ULONG)STATUS_PENDING;

  const auto status = pawnio_execute_async_nt(
    handle,
    name,
    overlapped->hEvent,
    nullptr,
    (ULONG_PTR)overlapped->hEvent & 1 ? nullptr : overlapped,
    &overlapped->Internal,
    in,
    in_size,
    out,
    out_size
  );

  if (NT_SUCCESS(status) && status != STATUS_PENDING) {
    return TRUE;
  }

  // We need to do this for STATUS_PENDING too, even though it isn't an error.
  SetLastError(RtlNtStatusToDosError(status));
  return FALSE;
}

PAWNIONTAPI pawnio_execute_async_nt(
  HANDLE handle,
  PCSTR name,
  HANDLE event,
  PVOID apc,
  PVOID apc_context,
  PVOID io_status_block,
  const ULONG64* in,
  SIZE_T in_size,
  PULONG64 out,
  SIZE_T out_size
) {
  const auto apc_routine = (PIO_APC_ROUTINE)apc;
  const auto iosb = (PIO_STATUS_BLOCK)io_status_block;

  char* p = nullptr;
  HANDLE heap = nullptr;
  void* heapalloc = nullptr;
  const auto allocsize = in_size * sizeof(*in) + FN_NAME_LENGTH;
  if (allocsize > 512) {
    heap = GetProcessHeap();
    heapalloc = HeapAlloc(heap, 0, allocsize);
    p = (char*)heapalloc;
    if (!p)
      return STATUS_NO_MEMORY;
  } else {
    p = (char*)_alloca(allocsize);
  }
  lstrcpynA(p, name, 31);
  p[31] = 0;
  if (in_size)
    RtlMoveMemory(p + 32, in, in_size * sizeof(*in));

  const auto status = NtDeviceIoControlFile(
    handle,
    event,
    apc_routine,
    apc_context,
    iosb,
    IOCTL_PIO_EXECUTE_FN,
    p,
    (ULONG)allocsize,
    out,
    (ULONG)(out_size * sizeof(*out))
  );
  // All PawnIO ioctls are buffered, so we're free to free this regardless of the status.
  if (heapalloc)
    HeapFree(heap, 0, p);
  return status;
}

PAWNIOAPI pawnio_close(HANDLE handle) {
  return nt_to_hresult(pawnio_close_nt(handle));
}

PAWNIOWINAPI pawnio_close_win32(HANDLE handle) {
  return nt_to_win32(pawnio_close_nt(handle));
}

PAWNIONTAPI pawnio_close_nt(HANDLE handle) {
  return NtClose(handle);
}

extern "C" BOOL WINAPI DllEntry(HINSTANCE, DWORD, LPVOID) {
  return TRUE;
}
