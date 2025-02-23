#include <windows.h>
#include <winioctl.h>
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>
#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>
#include <comdef.h>
#include <memory>

#pragma comment(lib, "vssapi.lib")

#define CHECK_HR_AND_FAIL(hr, msg) \
    if (FAILED(hr)) { \
        std::cerr << msg << " (hr=0x" << std::hex << hr << ")\n"; \
        return false; \
    }

class VSSBlockLevelBackup {
private:
    IVssBackupComponents* backupComponents = nullptr;
    VSS_ID snapshotSetId = GUID_NULL;
    VSS_ID snapshotId = GUID_NULL;
    std::wstring sourceVolume;
    std::wstring destFolder;

public:
    VSSBlockLevelBackup(const std::wstring& source, const std::wstring& destination)
        : sourceVolume(source), destFolder(destination) {
    }

    ~VSSBlockLevelBackup() {
        if (backupComponents) {
            backupComponents->Release();
            backupComponents = nullptr;
        }
        CoUninitialize();
    }

    bool Initialize() {
        HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
        CHECK_HR_AND_FAIL(hr, "COM initialization failed");

        hr = CreateVssBackupComponents(&backupComponents);
        CHECK_HR_AND_FAIL(hr, "VSS component creation failed");

        hr = backupComponents->InitializeForBackup();
        CHECK_HR_AND_FAIL(hr, "VSS backup initialization failed");

        hr = backupComponents->SetBackupState(true, true, VSS_BT_FULL, false);
        CHECK_HR_AND_FAIL(hr, "Setting backup state failed");

        return true;
    }

    bool CreateSnapshot() {
        HRESULT hr = backupComponents->StartSnapshotSet(&snapshotSetId);
        CHECK_HR_AND_FAIL(hr, "Snapshot set creation failed");

        hr = backupComponents->AddToSnapshotSet(
            const_cast<LPWSTR>(sourceVolume.c_str()),
            GUID_NULL, &snapshotId
        );
        CHECK_HR_AND_FAIL(hr, "Adding volume to snapshot failed");

        IVssAsync* prepareAsync = nullptr;
        hr = backupComponents->PrepareForBackup(&prepareAsync);
        CHECK_HR_AND_FAIL(hr, "PrepareForBackup failed");

        if (prepareAsync) {
            hr = prepareAsync->Wait();
            prepareAsync->Release();
            CHECK_HR_AND_FAIL(hr, "PrepareForBackup wait failed");
        }

        IVssAsync* snapshotAsync = nullptr;
        hr = backupComponents->DoSnapshotSet(&snapshotAsync);
        CHECK_HR_AND_FAIL(hr, "DoSnapshotSet failed");

        if (snapshotAsync) {
            hr = snapshotAsync->Wait();
            snapshotAsync->Release();
            CHECK_HR_AND_FAIL(hr, "Snapshot creation wait failed");
        }

        return true;
    }

    bool CreateBlockLevelBackup() {
        VSS_SNAPSHOT_PROP snapProp = { 0 };
        HRESULT hr = backupComponents->GetSnapshotProperties(snapshotId, &snapProp);
        if (FAILED(hr)) {
            std::cerr << "GetSnapshotProperties failed (hr=0x" << std::hex << hr << ")\n";
            return false;
        }

        std::wstring shadowDevice = snapProp.m_pwszSnapshotDeviceObject;
        std::wcout << L"Shadow device path: " << shadowDevice << L"\n";

        HANDLE hShadow = CreateFileW(
            shadowDevice.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_NO_BUFFERING,
            NULL
        );

        if (hShadow == INVALID_HANDLE_VALUE) {
            std::cerr << "Shadow device open failed (error=0x" << GetLastError() << ")\n";
            VssFreeSnapshotProperties(&snapProp);
            return false;
        }

        // Get volume size
        GET_LENGTH_INFORMATION lengthInfo = { 0 };
        DWORD bytesReturned = 0;
        if (!DeviceIoControl(
            hShadow,
            IOCTL_DISK_GET_LENGTH_INFO,
            NULL,
            0,
            &lengthInfo,
            sizeof(lengthInfo),
            &bytesReturned,
            NULL
        )) {
            std::cerr << "IOCTL_DISK_GET_LENGTH_INFO failed (error=0x" << GetLastError() << ")\n";
            CloseHandle(hShadow);
            VssFreeSnapshotProperties(&snapProp);
            return false;
        }

        // Create image file
        std::filesystem::path imagePath = std::filesystem::path(destFolder) / L"system_image.bin";
        std::ofstream imageFile(imagePath, std::ios::binary | std::ios::trunc);
        if (!imageFile) {
            std::wcerr << L"Failed to create image file: " << imagePath << L"\n";
            CloseHandle(hShadow);
            VssFreeSnapshotProperties(&snapProp);
            return false;
        }

        // Copy data in 1MB chunks
        const DWORD bufferSize = 1024 * 1024;
        std::unique_ptr<BYTE[]> buffer(new BYTE[bufferSize]);
        LARGE_INTEGER offset = { 0 };
        DWORD bytesRead = 0;

        std::wcout << L"Starting block-level backup ("
            << (lengthInfo.Length.QuadPart / (1024 * 1024))
            << L" MB)\n";

        while (offset.QuadPart < lengthInfo.Length.QuadPart) {
            if (!ReadFile(hShadow, buffer.get(), bufferSize, &bytesRead, NULL)) {
                std::cerr << "Read failed at offset " << offset.QuadPart
                    << " (error=0x" << GetLastError() << ")\n";
                break;
            }

            imageFile.write(reinterpret_cast<char*>(buffer.get()), bytesRead);
            offset.QuadPart += bytesRead;

            if ((offset.QuadPart / (1024 * 1024)) % 10 == 0) {
                std::wcout << L"Copied " << (offset.QuadPart / (1024 * 1024))
                    << L" MB...\n";
            }
        }

        CloseHandle(hShadow);
        VssFreeSnapshotProperties(&snapProp);
        std::wcout << L"Block-level backup completed to " << imagePath << L"\n";
        return true;
    }

    bool Cleanup() {
        if (backupComponents) {
            IVssAsync* cleanupAsync = nullptr;
            HRESULT hr = backupComponents->BackupComplete(&cleanupAsync);
            if (SUCCEEDED(hr) && cleanupAsync) {
                hr = cleanupAsync->Wait();
                cleanupAsync->Release();
            }
        }
        return true;
    }
};

bool CapturePhysicalDriveMetadata(int driveNumber, const std::wstring& destFolder) {
    std::wstring drivePath = L"\\\\.\\PhysicalDrive" + std::to_wstring(driveNumber);
    HANDLE hDrive = CreateFileW(
        drivePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hDrive == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Open drive failed (error=0x" << GetLastError() << L")\n";
        return false;
    }

    // Capture boot record
    const DWORD BOOT_RECORD_SIZE = 4096;
    std::unique_ptr<BYTE[]> bootRecord(new BYTE[BOOT_RECORD_SIZE]);
    DWORD bytesRead = 0;
    if (!ReadFile(hDrive, bootRecord.get(), BOOT_RECORD_SIZE, &bytesRead, NULL)) {
        std::wcerr << L"Boot record read failed (error=0x" << GetLastError() << L")\n";
        CloseHandle(hDrive);
        return false;
    }

    std::filesystem::path bootPath = std::filesystem::path(destFolder) / L"boot_record.bin";
    std::ofstream bootFile(bootPath, std::ios::binary);
    bootFile.write(reinterpret_cast<char*>(bootRecord.get()), bytesRead);
    std::wcout << L"Boot record saved to " << bootPath << L"\n";

    // Capture drive layout
    DWORD layoutSize = sizeof(DRIVE_LAYOUT_INFORMATION_EX) + 128 * sizeof(PARTITION_INFORMATION_EX);
    std::unique_ptr<BYTE[]> layoutBuffer(new BYTE[layoutSize]);
    if (!DeviceIoControl(
        hDrive,
        IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
        NULL,
        0,
        layoutBuffer.get(),
        layoutSize,
        &bytesRead,
        NULL
    )) {
        std::wcerr << L"Drive layout read failed (error=0x" << GetLastError() << L")\n";
        CloseHandle(hDrive);
        return false;
    }

    std::filesystem::path layoutPath = std::filesystem::path(destFolder) / L"drive_layout.bin";
    std::ofstream layoutFile(layoutPath, std::ios::binary);
    layoutFile.write(reinterpret_cast<char*>(layoutBuffer.get()), bytesRead);
    std::wcout << L"Drive layout saved to " << layoutPath << L"\n";

    CloseHandle(hDrive);
    return true;
}

bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID adminGroup = NULL;

    if (!AllocateAndInitializeSid(
        &ntAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &adminGroup
    )) {
        return false;
    }

    CheckTokenMembership(NULL, adminGroup, &isAdmin);
    FreeSid(adminGroup);
    return isAdmin == TRUE;
}

int wmain() {
    if (!IsRunningAsAdmin()) {
        std::wcerr << L"Run as administrator!\n";
        return 1;
    }

    std::wstring volume, destFolder, driveNumStr;
    int driveNumber = 0;

    std::wcout << L"Enter volume (e.g., C:\\): ";
    std::getline(std::wcin, volume);
    if (volume.empty()) volume = L"C:\\";

    std::wcout << L"Enter destination folder: ";
    std::getline(std::wcin, destFolder);
    if (destFolder.empty()) {
        std::wcerr << L"Invalid destination folder!\n";
        return 1;
    }

    std::wcout << L"Enter physical drive number: ";
    std::getline(std::wcin, driveNumStr);
    if (!driveNumStr.empty()) driveNumber = std::stoi(driveNumStr);

    try {
        std::filesystem::create_directories(destFolder);
    }
    catch (...) {
        std::wcerr << L"Failed to create destination directory!\n";
        return 1;
    }

    VSSBlockLevelBackup backup(volume, destFolder);
    if (!backup.Initialize()) return 1;
    if (!backup.CreateSnapshot()) return 1;
    if (!backup.CreateBlockLevelBackup()) return 1;
    if (!backup.Cleanup()) return 1;

    if (!CapturePhysicalDriveMetadata(driveNumber, destFolder)) {
        std::wcerr << L"Metadata capture failed!\n";
        return 1;
    }

    std::wcout << L"Backup completed successfully!\n";
    return 0;
}