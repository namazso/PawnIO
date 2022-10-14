#pragma once

constexpr static ULONG k_device_type = 41394;
constexpr static wchar_t k_device_path[] = L"\\Device\\PawnIO";
constexpr static wchar_t k_device_dospath[] = L"\\DosDevices\\PawnIO";
constexpr static wchar_t k_device_win32path[] = L"\\\\.\\PawnIO";

enum IoCtls : ULONG
{
  IOCTL_PIO_GET_REFCOUNT = CTL_CODE(k_device_type, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS),
  IOCTL_PIO_LOAD_BINARY = CTL_CODE(k_device_type, 0x821, METHOD_BUFFERED, FILE_ANY_ACCESS),
  IOCTL_PIO_EXECUTE_FN = CTL_CODE(k_device_type, 0x841, METHOD_BUFFERED, FILE_ANY_ACCESS)
};
