#include <pawnio.inc>

static bool:g_CallbackCalled = false;

static VAProc:g_CallbackVA;

public NTSTATUS:callback(VA:args);
public NTSTATUS:callback(VA:args) {
    g_CallbackCalled = true;
    debug_print(''Callback called!\n'');
    return STATUS_SUCCESS;
}

NTSTATUS:set_callback() {
    new VAProc:pKeInitializeApc = get_proc_address(''KeInitializeApc'');
    if (pKeInitializeApc == VAProc:NULL) {
        debug_print(''Failed to get KeInitializeApc address!\n'');
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    new VAProc:pKeGetCurrentThread = get_proc_address(''KeGetCurrentThread'');
    if (pKeGetCurrentThread == VAProc:NULL) {
        debug_print(''Failed to get KeGetCurrentThread address!\n'');
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    new VAProc:pKeInsertQueueApc = get_proc_address(''KeInsertQueueApc'');
    if (pKeInsertQueueApc == VAProc:NULL) {
        debug_print(''Failed to get KeInsertQueueApc address!\n'');
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    new VA:prkapc = virtual_alloc(0x58);
    if (prkapc == NULL) {
        debug_print(''Failed to allocate memory for APC!\n'');
        return STATUS_NO_MEMORY;
    }
    new current_thread = 0;
    invoke(pKeGetCurrentThread, current_thread);
    new unused = 0;
    invoke(
        pKeInitializeApc,
        unused, // -> VOID
        _:prkapc, // PRKAPC Apc
        current_thread, // PKTHREAD Thread
        2, // UCHAR Environment
        _:g_CallbackVA, // PKKERNEL_ROUTINE KernelRoutine
        0, // PKRUNDOWN_ROUTINE RundownRoutine
        0, // PKNORMAL_ROUTINE NormalRoutine
        0, // KPROCESSOR_MODE ProcessorMode
        _:prkapc // PVOID NormalContext
    );
    invoke(
        pKeInsertQueueApc,
        unused, // -> BOOLEAN
        _:prkapc, // PRKAPC Apc
        0, // PVOID SystemArgument1
        0, // PVOID SystemArgument2
        0 // KPRIORITY Increment
    );
    debug_print(''APC queued!\n'');
    return STATUS_SUCCESS;
}

DEFINE_IOCTL_SIZED(ioctl_test_callback, 0, 0) {
    return set_callback();
}

get_physical_address(VA:va) {
    static VAProc:pMmGetPhysicalAddress = VAProc:NULL;
    if (pMmGetPhysicalAddress == VAProc:NULL) {
        pMmGetPhysicalAddress = get_proc_address(''MmGetPhysicalAddress'');
        if (pMmGetPhysicalAddress == VAProc:NULL) {
            debug_print(''Failed to get MmGetPhysicalAddress address!\n'');
            return 0;
        }
    }
    new pa;
    invoke(pMmGetPhysicalAddress, pa, _:va);
    return pa;
}

NTSTATUS:do_memory_tests(VA:alloc) {
    new alloc_pa = get_physical_address(alloc);
    if (alloc_pa == 0) {
        debug_print(''Failed to get physical address!\n'');
        return STATUS_UNSUCCESSFUL;
    }

    new NTSTATUS:status = STATUS_SUCCESS;

    debug_print(''Virtual address: %x, Physical address: %x\n'', _:alloc, _:alloc_pa);

    status = virtual_write_qword(alloc, 0x1122334455667788);
    if (!NT_SUCCESS(status)) {
        debug_print(''Failed to write to virtual memory!\n'');
        return status;
    }

    new temp;
    status = virtual_read_qword(alloc, temp);
    if (!NT_SUCCESS(status)) {
        debug_print(''Failed to read QWORD from virtual memory: %x\n'', _:status);
        return status;
    }
    if (temp != 0x1122334455667788) {
        debug_print(''Data read from virtual memory does not match data written!\n'');
        return STATUS_UNSUCCESSFUL;
    }
    status = virtual_read_dword(alloc, temp);
    if (!NT_SUCCESS(status)) {
        debug_print(''Failed to read DWORD from virtual memory: %x\n'', _:status);
        return status;
    }
    if (temp != 0x55667788) {
        debug_print(''Data read from virtual memory does not match data written!\n'');
        return STATUS_UNSUCCESSFUL;
    }
    status = virtual_read_word(alloc, temp);
    if (!NT_SUCCESS(status)) {
        debug_print(''Failed to read WORD from virtual memory: %x\n'', _:status);
        return status;
    }
    if (temp != 0x7788) {
        debug_print(''Data read from virtual memory does not match data written!\n'');
        return STATUS_UNSUCCESSFUL;
    }
    status = virtual_read_byte(alloc, temp);
    if (!NT_SUCCESS(status)) {
        debug_print(''Failed to read BYTE from virtual memory: %x\n'', _:status);
        return status;
    }
    if (temp != 0x88) {
        debug_print(''Data read from virtual memory does not match data written!\n'');
        return STATUS_UNSUCCESSFUL;
    }

    /*status = physical_read_qword(alloc_pa, temp);
    if (!NT_SUCCESS(status)) {
        debug_print(''Failed to read QWORD from physical memory: %x\n'', _:status);
        return status;
    }
    if (temp != 0x1122334455667788) {
        debug_print(''Data read from physical memory does not match data written!\n'');
        return STATUS_UNSUCCESSFUL;
    }
    status = physical_read_dword(alloc_pa, temp);
    if (!NT_SUCCESS(status)) {
        debug_print(''Failed to read DWORD from physical memory: %x\n'', _:status);
        return status;
    }
    if (temp != 0x55667788) {
        debug_print(''Data read from physical memory does not match data written!\n'');
        return STATUS_UNSUCCESSFUL;
    }
    status = physical_read_word(alloc_pa, temp);
    if (!NT_SUCCESS(status)) {
        debug_print(''Failed to read WORD from physical memory: %x\n'', _:status);
        return status;
    }
    if (temp != 0x7788) {
        debug_print(''Data read from physical memory does not match data written!\n'');
        return STATUS_UNSUCCESSFUL;
    }
    status = physical_read_byte(alloc_pa, temp);
    if (!NT_SUCCESS(status)) {
        debug_print(''Failed to read BYTE from physical memory: %x\n'', _:status);
        return status;
    }
    if (temp != 0x88) {
        debug_print(''Data read from physical memory does not match data written!\n'');
        return STATUS_UNSUCCESSFUL;
    }*/

    virtual_write_qword(alloc, 0x1122334455667788);
    status = virtual_cmpxchg_qword2(alloc, 0x8877665544332211, 0x1122334455667788);
    if (!NT_SUCCESS(status)) {
        debug_print(''Failed to perform cmpxchg QWORD: %x\n'', _:status);
        return status;
    }
    status = virtual_cmpxchg_qword2(alloc, 0x8877665544332211, 0x1122334455667788);
    if (status != STATUS_UNSUCCESSFUL) {
        debug_print(''cmpxchg should have failed because the expected value does not match the current value!\n'');
        return STATUS_UNSUCCESSFUL;
    }

    
    virtual_write_qword(alloc, 0x1122334455667788);
    status = virtual_cmpxchg_dword2(alloc, 0x11223344, 0x55667788);
    if (!NT_SUCCESS(status)) {
        debug_print(''Failed to perform cmpxchg DWORD: %x\n'', _:status);
        return status;
    }
    status = virtual_cmpxchg_dword2(alloc, 0x11223344, 0x55667788);
    if (status != STATUS_UNSUCCESSFUL) {
        debug_print(''cmpxchg should have failed because the expected value does not match the current value!\n'');
        return STATUS_UNSUCCESSFUL;
    }

    virtual_write_qword(alloc, 0x1122334455667788);
    status = virtual_cmpxchg_word2(alloc, 0x5566, 0x7788);
    if (!NT_SUCCESS(status)) {
        debug_print(''Failed to perform cmpxchg WORD: %x\n'', _:status);
        return status;
    }
    status = virtual_cmpxchg_word2(alloc, 0x5566, 0x7788);
    if (status != STATUS_UNSUCCESSFUL) {
        debug_print(''cmpxchg should have failed because the expected value does not match the current value!\n'');
        return STATUS_UNSUCCESSFUL;
    }

    virtual_write_qword(alloc, 0x1122334455667788);
    status = virtual_cmpxchg_byte2(alloc, 0x77, 0x88);
    if (!NT_SUCCESS(status)) {
        debug_print(''Failed to perform cmpxchg BYTE: %x\n'', _:status);
        return status;
    }
    status = virtual_cmpxchg_byte2(alloc, 0x77, 0x88);
    if (status != STATUS_UNSUCCESSFUL) {
        debug_print(''cmpxchg should have failed because the expected value does not match the current value!\n'');
        return STATUS_UNSUCCESSFUL;
    }

    virtual_write_qword(alloc, 0x1122334455667788);
    new VA:map = io_space_map(alloc_pa, 0x1000);
    if (map == NULL) {
        debug_print(''Failed to map IO space!\n'');
        return STATUS_UNSUCCESSFUL;
    }
    status = virtual_read_qword(map, temp);
    io_space_unmap(map, 0x1000);
    if (!NT_SUCCESS(status)) {
        debug_print(''io_space_map is broken!\n'');
        return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS:do_pci_tests() {
    new temp;
    new NTSTATUS:status = STATUS_SUCCESS;

    temp = 0xFFFFFFFFFFFFFFFF;
    status = pci_config_read_qword(0, 0, 0, 0, temp);
    if (status == STATUS_DEVICE_DOES_NOT_EXIST) {
        debug_print(''No PCI bus found, skipping PCI tests.\n'');
        return STATUS_SUCCESS;
    }
    if (!NT_SUCCESS(status)) {
        debug_print(''Failed to read PCI config space: %x\n'', _:status);
        return status;
    }
    if (temp == 0xFFFFFFFFFFFFFFFF) {
        debug_print(''Failed to read PCI config space!\n'');
        return STATUS_UNSUCCESSFUL;
    }

    temp = 0xFFFFFFFF;
    status = pci_config_read_dword(0, 0, 0, 0, temp);
    if (!NT_SUCCESS(status)) {
        debug_print(''Failed to read PCI config space: %x\n'', _:status);
        return status;
    }
    if (temp == 0xFFFFFFFF) {
        debug_print(''Failed to read PCI config space!\n'');
        return STATUS_UNSUCCESSFUL;
    }

    temp = 0xFFFF;
    status = pci_config_read_word(0, 0, 0, 0, temp);
    if (!NT_SUCCESS(status)) {
        debug_print(''Failed to read PCI config space: %x\n'', _:status);
        return status;
    }
    if (temp == 0xFFFF) {
        debug_print(''Failed to read PCI config space!\n'');
        return STATUS_UNSUCCESSFUL;
    }

    temp = 0xFF;
    status = pci_config_read_byte(0, 0, 0, 0, temp);
    if (!NT_SUCCESS(status)) {
        debug_print(''Failed to read PCI config space: %x\n'', _:status);
        return status;
    }
    if (temp == 0xFF) {
        debug_print(''Failed to read PCI config space!\n'');
        return STATUS_UNSUCCESSFUL;
    }

    // Write not tested.

    return STATUS_SUCCESS;
}

DEFINE_IOCTL_SIZED(ioctl_test, 0, 0) {
    if (!g_CallbackCalled) {
        debug_print(''Callback was not called yet!\n'');
        return STATUS_UNSUCCESSFUL;
    }

    if (get_arch() != ARCH_X64) {
        // We actually should never get here due to our imports
        debug_print(''This test is only supported on x64!\n'');
        return STATUS_NOT_SUPPORTED;
    }

    if (cpu_count() < 1) {
        debug_print(''cpu_count is broken!\n'');
        return STATUS_UNSUCCESSFUL;
    }

    new NTSTATUS:status = STATUS_SUCCESS;

    /*new old_affinity[2];
    status = cpu_set_affinity(0, old_affinity);
    if (!NT_SUCCESS(status)) {
        debug_print(''cpu_set_affinity failed with %x!\n'', _:status);
        return status;
    }
    status = cpu_restore_affinity(old_affinity);
    if (!NT_SUCCESS(status)) {
        debug_print(''cpu_restore_affinity failed with %x!\n'', _:status);
        return status;
    }*/

    new efer;
    interrupts_disable();
    status = msr_read(0xC0000080, efer);
    if (NT_SUCCESS(status)) {
        status = msr_write(0xC0000080, efer); // Write it back
    }
    interrupts_enable();

    if (!NT_SUCCESS(status)) {
        debug_print(''msr_read or msr_write failed with %x!\n'', _:status);
        return status;
    }

    new invalid_gsbase = 0xDEADBEEFCAFEBABE;
    status = msr_write(0xC0000102, invalid_gsbase);
    if (SIGN_EXTEND32(_:status) != _:STATUS_PRIVILEGED_INSTRUCTION) {
        debug_print(''msr_write to GS_BASE should have failed. Actual: %x\n'', _:status);
        return STATUS_UNSUCCESSFUL;
    }

    new VA:alloc = virtual_alloc(0x1000);
    if (alloc == NULL) {
        debug_print(''Failed to allocate memory!\n'');
        return STATUS_NO_MEMORY;
    }

    status = do_memory_tests(alloc);
    virtual_free(alloc);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = do_pci_tests();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = microsleep(1000);
    if (!NT_SUCCESS(status)) {
        debug_print(''microsleep failed with %x!\n'', _:status);
        return status;
    }

    microsleep2(1000);

    new frequency;
    new counter = qpc(frequency);

    debug_print(''QPC frequency: %d, Counter: %d\n'', _:frequency, _:counter);

    // IO ports not tested

    new CpuVendor:vendor = get_cpu_vendor();
    if (vendor != CpuVendor_Intel && vendor != CpuVendor_AMD && vendor != CpuVendor_VIA && vendor != CpuVendor_Hygon) {
        debug_print(''Unknown CPU vendor %x!\n'', _:vendor);
        // Probably something is terribly wrong, quite unlikely a new vendor appeared
        return STATUS_UNSUCCESSFUL;
    }

    new cr0 = cr_read(0);
    if (!(cr0 & 1)) {
        debug_print(''CR0 should have the protection bit enabled!\n'');
        return STATUS_UNSUCCESSFUL;
    }

    new dr6 = dr_read(6);
    if ((dr6 & 0x7F0) != 0x7F0) {
        debug_print(''DR6 should have bits 4-11 set!\n'');
        return STATUS_UNSUCCESSFUL;
    }

    new tsc = rdtsc();
    debug_print(''TSC: %d\n'', _:tsc);

    new limit, base;
    sidt(limit, base);
    debug_print(''IDT base: %x, limit: %x\n'', _:base, _:limit);

    sgdt(limit, base);
    debug_print(''GDT base: %x, limit: %x\n'', _:base, _:limit);

    new mxcsr = mxcsr_read();
    debug_print(''MXCSR: %x\n'', _:mxcsr);

    return STATUS_SUCCESS;
}

NTSTATUS:main() {
    new AmxCip:callback_addr = get_public(''callback'');
    if (callback_addr == AmxCip:0) {
        debug_print(''Failed to get callback address!\n'');
        return STATUS_UNSUCCESSFUL;
    }
    debug_print(''Callback AMX address: %x\n'', _:callback_addr);

    g_CallbackVA = callback_alloc(callback_addr);
    if (g_CallbackVA == VAProc:0) {
        debug_print(''Failed to allocate callback!\n'');
        return STATUS_UNSUCCESSFUL;
    }
    debug_print(''Callback native VA: %x\n'', _:g_CallbackVA);

    return STATUS_SUCCESS;
}

public NTSTATUS:unload() {
    callback_free(g_CallbackVA);

    debug_print(''Test module unloaded!\n'');
    return STATUS_SUCCESS;
}
