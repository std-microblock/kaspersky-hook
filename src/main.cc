#include <ntddk.h>
#include <wdf.h>

#include "logger.hpp"

EVT_WDF_DRIVER_DEVICE_ADD KmdfDeviceAdd;
EVT_WDF_OBJECT_CONTEXT_CLEANUP DriverCleanup;

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                                _In_ PUNICODE_STRING RegistryPath) {
    WDF_DRIVER_CONFIG config;
    NTSTATUS status;

    LOG_INFO("Hello, World!");

    // WDF Init or not
    if constexpr (false) {
        WDF_DRIVER_CONFIG_INIT(&config, KmdfDeviceAdd);
        config.EvtDriverUnload = (PFN_WDF_DRIVER_UNLOAD)DriverCleanup;

        status =
            WdfDriverCreate(DriverObject, RegistryPath,
                            WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);

        return status;
    } else {
        return STATUS_FAILED_DRIVER_ENTRY;
    }
}

NTSTATUS
KmdfDeviceAdd(_In_ WDFDRIVER Driver, _Inout_ PWDFDEVICE_INIT DeviceInit) {
    UNREFERENCED_PARAMETER(Driver);

    WDFDEVICE device;
    NTSTATUS status;

    status = WdfDeviceCreate(&DeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &device);

    return status;
}

VOID DriverCleanup(_In_ WDFOBJECT Driver) {
    UNREFERENCED_PARAMETER(Driver);
}
