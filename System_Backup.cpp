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
#include <algorithm>

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
        if (backupComponents) backupComponents->Release();
        CoUninitialize();
    }

    bool Initialize() {
        HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
        CHECK_HR_AND_FAIL(hr, "Failed to initialize COM");

        hr = CreateVssBackupComponents(&backupComponents);
        CHECK_HR_AND_FAIL(hr, "Failed to create VSS backup components");

        hr = backupComponents->InitializeForBackup();
        CHECK_HR_AND_FAIL(hr, "Failed to initialize for backup");

        hr = backupComponents->SetBackupState(true, true, VSS_BT_FULL, false);
        CHECK_HR_AND_FAIL(hr, "Failed to set backup state");

        return true;
    }

    bool CreateSnapshot() {
        HRESULT hr = backupComponents->StartSnapshotSet(&snapshotSetId);
        CHECK_HR_AND_FAIL(hr, "Failed to start snapshot set");

        hr = backupComponents->AddToSnapshotSet(const_cast<LPWSTR>(sourceVolume.c_str()),
            GUID_NULL, &snapshotId);
        CHECK_HR_AND_FAIL(hr, "Failed to add volume to snapshot set");

        IVssAsync* prepareAsync = nullptr;
        hr = backupComponents->PrepareForBackup(&prepareAsync);
        CHECK_HR_AND_FAIL(hr, "PrepareForBackup failed");
        if (prepareAsync) {
            hr = prepareAsync->Wait();
            prepareAsync->Release();
            CHECK_HR_AND_FAIL(hr, "PrepareForBackup Wait() failed");
        }

        IVssAsync* snapshotAsync = nullptr;
        hr = backupComponents->DoSnapshotSet(&snapshotAsync);
        CHECK_HR_AND_FAIL(hr, "DoSnapshotSet failed");
        if (snapshotAsync) {
            hr = snapshotAsync->Wait();
            snapshotAsync->Release();
            CHECK_HR_AND_FAIL(hr, "DoSnapshotSet Wait() failed");
        }

        return true;
    }

    bool CreateBlockLevelBackup() {
        VSS_SNAPSHOT_PROP snapProp = { 0 };
        HRESULT hr = backupComponents->GetSnapshotProperties(snapshotId, &snapProp);
        if (FAILED(hr)) {
            std::cerr << "Failed to get snapshot properties (hr=0x" << std::hex << hr << ")\n";
            return false;
        }

        std::wstring shadowDevice = snapProp.m_pwszSnapshotDeviceObject;
        std::wcout << L"Using shadow copy device: " << shadowDevice << std::endl;

        // Open the shadow copy volume for raw access
        HANDLE hShadow = CreateFileW(shadowDevice.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (hShadow == INVALID_HANDLE_VALUE) {
            std::wcerr << L"Failed to open shadow device (error=0x"
                << GetLastError() << L")\n";
            VssFreeSnapshotProperties(&snapProp);
            return false;
        }

        // Get volume size
        GET_LENGTH_INFORMATION lengthInfo = { 0 };
        DWORD bytesReturned = 0;
        if (!DeviceIoControl(hShadow, IOCTL_DISK_GET_LENGTH_INFO,
            NULL, 0, &lengthInfo, sizeof(lengthInfo), &bytesReturned, NULL)) {
            std::cerr << "Failed to get volume size (error=0x"
                << GetLastError() << ")\n";
            CloseHandle(hShadow);
            VssFreeSnapshotProperties(&snapProp);
            return false;
        }

        // Create system image file
        std::filesystem::path imagePath = std::filesystem::path(destFolder) / L"system_image.bin";
        std::ofstream imageFile(imagePath, std::ios::binary | std::ios::trunc);
        if (!imageFile) {
            std::wcerr << L"Failed to create image file: " << imagePath << std::endl;
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
            << L" MB total)" << std::endl;

        while (offset.QuadPart < lengthInfo.Length.QuadPart) {
            if (!ReadFile(hShadow, buffer.get(), bufferSize, &bytesRead, NULL)) {
                std::cerr << "Read failed at offset " << offset.QuadPart
                    << " (error=0x" << GetLastError() << ")\n";
                break;
            }

            imageFile.write(reinterpret_cast<char*>(buffer.get()), bytesRead);
            offset.QuadPart += bytesRead;

            // Progress output
            if ((offset.QuadPart / bufferSize) % 10 == 0) {
                std::wcout << L"Copied " << (offset.QuadPart / (1024 * 1024))
                    << L" MB..." << std::endl;
            }
        }

        CloseHandle(hShadow);
        VssFreeSnapshotProperties(&snapProp);
        std::wcout << L"Block-level backup completed to " << imagePath << std::endl;
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

bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    return isAdmin;
}

// (Keep the CapturePhysicalDriveMetadata, isDriveLetterAvailable, and IsRunningAsAdmin functions from original code)

int wmain() {
    if (!IsRunningAsAdmin()) {
        std::wcerr << L"Requires administrator privileges.\n";
        return 1;
    }

    std::wstring volume = L"C:\\";
    std::wstring destFolder = L"D:\\Backup";
    int driveNumber = 0;

    // (Keep user input handling from original code)

    VSSBlockLevelBackup backup(volume, destFolder);
    if (!backup.Initialize()) return 1;
    if (!backup.CreateSnapshot()) return 1;
    if (!backup.CreateBlockLevelBackup()) return 1;
    if (!backup.Cleanup()) return 1;

    // (Keep metadata capture from original code)

    return 0;
}