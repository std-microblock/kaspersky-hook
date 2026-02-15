#include "syscall.hpp"

#include <ntimage.h>
#include <cstring>

#include "error.hpp"

namespace {

struct ImageCache {
    PUCHAR base = nullptr;
    SIZE_T size = 0;
};

constexpr ULONG kSyscallTag = 'cSyS';

ImageCache g_ntdll = {};
ImageCache g_win32u = {};

void free_image(ImageCache* cache) {
    if (!cache) {
        return;
    }

    if (cache->base) {
        ExFreePoolWithTag(cache->base, kSyscallTag);
        cache->base = nullptr;
        cache->size = 0;
    }
}

core::Result<PUCHAR> load_image_from_file(const wchar_t* path,
                                          ImageCache* cache) {
    if (!path || !cache) {
        return core::err(core::ErrorCode::InvalidArgument);
    }

    if (cache->base) {
        return cache->base;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return core::err(core::ErrorCode::InvalidArgument);
    }

    UNICODE_STRING file_name{};
    RtlInitUnicodeString(&file_name, path);

    OBJECT_ATTRIBUTES oa{};
    InitializeObjectAttributes(&oa, &file_name,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               nullptr, nullptr);

    HANDLE file_handle = nullptr;
    IO_STATUS_BLOCK io{};

    auto status = ZwCreateFile(
        &file_handle, GENERIC_READ, &oa, &io, nullptr, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);

    if (!NT_SUCCESS(status)) {
        return core::err(core::ErrorCode::NotFound);
    }

    FILE_STANDARD_INFORMATION std_info{};
    status = ZwQueryInformationFile(file_handle, &io, &std_info,
                                    sizeof(std_info), FileStandardInformation);

    if (!NT_SUCCESS(status) || std_info.EndOfFile.QuadPart == 0) {
        ZwClose(file_handle);
        return core::err(core::ErrorCode::NotFound);
    }

    const auto file_size = static_cast<ULONG>(std_info.EndOfFile.QuadPart);
    auto file_buffer = reinterpret_cast<PUCHAR>(
        ExAllocatePoolWithTag(PagedPool, file_size, kSyscallTag));

    if (!file_buffer) {
        ZwClose(file_handle);
        return core::err(core::ErrorCode::OutOfRange);
    }

    LARGE_INTEGER offset{};
    status = ZwReadFile(file_handle, nullptr, nullptr, nullptr, &io, file_buffer,
                        file_size, &offset, nullptr);

    ZwClose(file_handle);

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(file_buffer, kSyscallTag);
        return core::err(core::ErrorCode::NotFound);
    }

    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(file_buffer);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        ExFreePoolWithTag(file_buffer, kSyscallTag);
        return core::err(core::ErrorCode::NotFound);
    }

    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(file_buffer + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        ExFreePoolWithTag(file_buffer, kSyscallTag);
        return core::err(core::ErrorCode::NotFound);
    }

    auto image = reinterpret_cast<PUCHAR>(
        ExAllocatePoolWithTag(NonPagedPool, nt->OptionalHeader.SizeOfImage,
                              kSyscallTag));

    if (!image) {
        ExFreePoolWithTag(file_buffer, kSyscallTag);
        return core::err(core::ErrorCode::OutOfRange);
    }

    RtlZeroMemory(image, nt->OptionalHeader.SizeOfImage);
    RtlCopyMemory(image, file_buffer, nt->OptionalHeader.SizeOfHeaders);

    auto section = IMAGE_FIRST_SECTION(nt);
    for (unsigned short i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (section[i].SizeOfRawData == 0 || section[i].PointerToRawData == 0) {
            continue;
        }

        RtlCopyMemory(image + section[i].VirtualAddress,
                      file_buffer + section[i].PointerToRawData,
                      section[i].SizeOfRawData);
    }

    ExFreePoolWithTag(file_buffer, kSyscallTag);

    cache->base = image;
    cache->size = nt->OptionalHeader.SizeOfImage;

    return image;
}

PVOID get_export(PUCHAR image, const char* name) {
    if (!image || !name) {
        return nullptr;
    }

    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(image);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return nullptr;
    }

    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(image + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return nullptr;
    }

    const auto& export_dir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!export_dir.VirtualAddress || !export_dir.Size) {
        return nullptr;
    }

    auto exports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
        image + export_dir.VirtualAddress);

    auto names = reinterpret_cast<PULONG>(image + exports->AddressOfNames);
    auto ordinals = reinterpret_cast<PUSHORT>(image + exports->AddressOfNameOrdinals);
    auto functions = reinterpret_cast<PULONG>(image + exports->AddressOfFunctions);

    for (ULONG i = 0; i < exports->NumberOfNames; i++) {
        auto function_name = reinterpret_cast<const char*>(image + names[i]);
        if (!strcmp(function_name, name)) {
            auto ordinal = ordinals[i];
            auto rva = functions[ordinal];
            return image + rva;
        }
    }

    return nullptr;
}

core::Result<ULONG> extract_syscall_number(PUCHAR fn) {
    if (!fn) {
        return core::err(core::ErrorCode::NotFound);
    }

    for (int i = 0; i < 32; ++i) {
        if (fn[i] == 0xC2 || fn[i] == 0xC3) {
            break;
        }

        if (fn[i] == 0xB8) {
            return *reinterpret_cast<PULONG>(fn + i + 1);
        }
    }

    return core::err(core::ErrorCode::NotFound);
}

}  // namespace

namespace core {

Result<ULONG> get_syscall_number(const char* syscall_name) {
    if (!syscall_name) {
        return core::err(core::ErrorCode::InvalidArgument);
    }

    auto image_result = load_image_from_file(L"\\SystemRoot\\System32\\ntdll.dll",
                                             &g_ntdll);
    if (!image_result) {
        return core::err(image_result.error());
    }

    auto fn = reinterpret_cast<PUCHAR>(get_export(image_result.value(), syscall_name));
    if (!fn) {
        return core::err(core::ErrorCode::NotFound);
    }

    return extract_syscall_number(fn);
}

Result<ULONG> get_shadow_syscall_number(const char* syscall_name) {
    if (!syscall_name) {
        return core::err(core::ErrorCode::InvalidArgument);
    }

    auto image_result = load_image_from_file(L"\\SystemRoot\\System32\\win32u.dll",
                                             &g_win32u);
    if (!image_result) {
        return core::err(image_result.error());
    }

    auto fn = reinterpret_cast<PUCHAR>(get_export(image_result.value(), syscall_name));
    if (!fn) {
        return core::err(core::ErrorCode::NotFound);
    }

    return extract_syscall_number(fn);
}

void unload_syscall_images() {
    free_image(&g_ntdll);
    free_image(&g_win32u);
}

}  // namespace core
