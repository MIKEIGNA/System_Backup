#include <windows.h>
#include <winioctl.h>       // For IOCTL_DISK_GET_LENGTH_INFO
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>
#include <iostream>
#include <string>
#include <filesystem>
#include <comdef.h>
#include <memory>
#include <algorithm>

// Link with vssapi.lib and other Windows libraries as needed
#pragma comment(lib, "vssapi.lib")

// Helper macro for HRESULT checking and logging
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
    std::wstring sourceDrive;
    std::wstring imagePath;

public:
    VSSBlockLevelBackup(const std::wstring& source, const std::wstring& imgFile)
        : sourceDrive(source), imagePath(imgFile) {
    }

    ~VSSBlockLevelBackup() {
        if (backupComponents) {
            backupComponents->Release();
        }
        CoUninitialize();
    }

    bool Initialize() {
        // Using C++20 so this code is compiled with /std:c++20 in your project
        HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
        CHECK_HR_AND_FAIL(hr, "Failed to initialize COM");

        hr = CreateVssBackupComponents(&backupComponents);
        CHECK_HR_AND_FAIL(hr, "Failed to create VSS backup components");

        hr = backupComponents->InitializeForBackup();
        CHECK_HR_AND_FAIL(hr, "Failed to InitializeForBackup");

        hr = backupComponents->SetBackupState(
            /*bSelectComponents=*/true,
            /*bBackupBootableSystemState=*/true,
            VSS_BT_FULL,
            /*bPartialFileSupport=*/false
        );
        CHECK_HR_AND_FAIL(hr, "Failed to set backup state");

        return true;
    }

    bool CreateSnapshot() {
        // Start snapshot set
        HRESULT hr = backupComponents->StartSnapshotSet(&snapshotSetId);
        CHECK_HR_AND_FAIL(hr, "Failed to start snapshot set");

        // Add the volume (e.g., "C:\") to the snapshot set. Note: cast to LPWSTR is needed.
        hr = backupComponents->AddToSnapshotSet(
            const_cast<LPWSTR>(sourceDrive.c_str()),
            GUID_NULL,
            &snapshotId
        );
        CHECK_HR_AND_FAIL(hr, "Failed to add volume to snapshot set");

        // Prepare for backup
        {
            IVssAsync* pAsync = nullptr;
            hr = backupComponents->PrepareForBackup(&pAsync);
            CHECK_HR_AND_FAIL(hr, "PrepareForBackup failed");
            if (pAsync) {
                hr = pAsync->Wait();
                pAsync->Release();
                CHECK_HR_AND_FAIL(hr, "PrepareForBackup Wait() failed");
            }
        }

        // Create snapshot
        {
            IVssAsync* pAsyncSnapshot = nullptr;
            hr = backupComponents->DoSnapshotSet(&pAsyncSnapshot);
            CHECK_HR_AND_FAIL(hr, "DoSnapshotSet failed");
            if (pAsyncSnapshot) {
                hr = pAsyncSnapshot->Wait();
                pAsyncSnapshot->Release();
                CHECK_HR_AND_FAIL(hr, "DoSnapshotSet Wait() failed");
            }
        }

        return true;
    }

    bool BackupToImage() {
        // Retrieve snapshot properties using the snapshotId
        VSS_SNAPSHOT_PROP snapProp;
        ZeroMemory(&snapProp, sizeof(snapProp));

        HRESULT hr = backupComponents->GetSnapshotProperties(snapshotId, &snapProp);
        if (FAILED(hr)) {
            std::cerr << "Failed to get snapshot properties (hr=0x"
                << std::hex << hr << ")\n";
            return false;
        }

        // Validate the shadow copy device path
        std::wstring shadowPath = snapProp.m_pwszSnapshotDeviceObject;
        if (shadowPath.empty()) {
            std::cerr << "Snapshot device path is empty.\n";
            VssFreeSnapshotProperties(&snapProp);
            return false;
        }
        std::wcout << L"Shadow copy device: " << shadowPath << std::endl;

        // Open the shadow copy device for raw reading
        HANDLE hShadow = CreateFileW(
            shadowPath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_NO_BUFFERING,  // Optional flag to reduce caching overhead
            NULL
        );
        if (hShadow == INVALID_HANDLE_VALUE) {
            std::cerr << "Failed to open shadow device for reading (error=0x"
                << std::hex << GetLastError() << ")\n";
            VssFreeSnapshotProperties(&snapProp);
            return false;
        }

        // Get the total volume size
        GET_LENGTH_INFORMATION lengthInfo;
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
        ))
        {
            std::cerr << "IOCTL_DISK_GET_LENGTH_INFO failed (error=0x"
                << std::hex << GetLastError() << ")\n";
            CloseHandle(hShadow);
            VssFreeSnapshotProperties(&snapProp);
            return false;
        }

        ULONGLONG totalBytes = lengthInfo.Length.QuadPart;
        std::wcout << L"Volume size: " << totalBytes << L" bytes\n";

        // Ensure the destination directory exists
        std::filesystem::path outPath = imagePath;
        if (outPath.has_parent_path()) {
            std::filesystem::create_directories(outPath.parent_path());
        }

        // Open the output image file
        HANDLE hImgFile = CreateFileW(
            imagePath.c_str(),
            GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        if (hImgFile == INVALID_HANDLE_VALUE) {
            std::cerr << "Failed to create output image file (error=0x"
                << std::hex << GetLastError() << ")\n";
            CloseHandle(hShadow);
            VssFreeSnapshotProperties(&snapProp);
            return false;
        }

        const DWORD BUF_SIZE = 1024 * 1024; // 1 MB buffer
        std::unique_ptr<char[]> buffer(new char[BUF_SIZE]);
        LARGE_INTEGER offset;
        offset.QuadPart = 0;
        ULONGLONG bytesReadTotal = 0;

        // Read the entire volume in chunks
        while (bytesReadTotal < totalBytes) {
            DWORD toRead = (DWORD)std::min<ULONGLONG>(BUF_SIZE, totalBytes - bytesReadTotal);
            DWORD dwRead = 0;

            if (!SetFilePointerEx(hShadow, offset, NULL, FILE_BEGIN)) {
                std::cerr << "SetFilePointerEx failed at offset " << offset.QuadPart
                    << " (error=0x" << std::hex << GetLastError() << ")\n";
                break;
            }

            BOOL ok = ReadFile(hShadow, buffer.get(), toRead, &dwRead, NULL);
            if (!ok) {
                DWORD err = GetLastError();
                std::cerr << "ReadFile failed at offset " << offset.QuadPart
                    << " (error=0x" << std::hex << err << ")\n";
                break;
            }
            if (dwRead == 0) {
                // Unexpected end of file
                break;
            }

            DWORD dwWritten = 0;
            ok = WriteFile(hImgFile, buffer.get(), dwRead, &dwWritten, NULL);
            if (!ok || dwWritten != dwRead) {
                std::cerr << "WriteFile failed at offset " << offset.QuadPart
                    << " (error=0x" << std::hex << GetLastError() << ")\n";
                break;
            }

            offset.QuadPart += dwRead;
            bytesReadTotal += dwRead;
        }

        std::wcout << L"Finished reading " << bytesReadTotal
            << L" bytes out of " << totalBytes << L"\n";

        CloseHandle(hImgFile);
        CloseHandle(hShadow);
        VssFreeSnapshotProperties(&snapProp);

        if (bytesReadTotal != totalBytes) {
            std::cerr << "Incomplete backup: read " << bytesReadTotal
                << " bytes, expected " << totalBytes << " bytes.\n";
            return false;
        }
        return true;
    }

    bool Cleanup() {
        if (backupComponents) {
            IVssAsync* pAsync = nullptr;
            HRESULT hr = backupComponents->BackupComplete(&pAsync);
            if (FAILED(hr)) {
                std::cerr << "BackupComplete failed (hr=0x" << std::hex << hr << ")\n";
                return false;
            }
            if (pAsync) {
                hr = pAsync->Wait();
                pAsync->Release();
                if (FAILED(hr)) {
                    std::cerr << "BackupComplete Wait() failed (hr=0x"
                        << std::hex << hr << ")\n";
                    return false;
                }
            }
        }
        return true;
    }
};

static bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (!AllocateAndInitializeSid(&ntAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup))
    {
        std::cerr << "Failed to initialize SID\n";
        return false;
    }

    if (!CheckTokenMembership(NULL, adminGroup, &isAdmin)) {
        FreeSid(adminGroup);
        std::cerr << "Failed to check token membership\n";
        return false;
    }

    FreeSid(adminGroup);
    return (isAdmin == TRUE);
}

int wmain() {
    if (!IsRunningAsAdmin()) {
        std::wcerr << L"This program requires administrator privileges.\n";
        return 1;
    }

    std::wstring volume;
    std::wstring destImg;

    std::wcout << L"Enter volume to snapshot (e.g., C:\\): ";
    std::getline(std::wcin, volume);
    if (volume.empty()) {
        volume = L"C:\\";
    }

    std::wcout << L"Enter path to output .img file (e.g., D:\\Backups\\MyDisk.img): ";
    std::getline(std::wcin, destImg);
    if (destImg.empty()) {
        std::wcerr << L"No destination path provided.\n";
        return 1;
    }

    VSSBlockLevelBackup backup(volume, destImg);

    if (!backup.Initialize()) {
        std::cerr << "Initialization failed.\n";
        return 1;
    }

    std::cout << "Creating snapshot...\n";
    if (!backup.CreateSnapshot()) {
        std::cerr << "CreateSnapshot failed.\n";
        return 1;
    }

    std::cout << "Performing block-level backup to image...\n";
    if (!backup.BackupToImage()) {
        std::cerr << "BackupToImage failed.\n";
        // We attempt Cleanup even if backup failed.
    }

    std::cout << "Cleaning up...\n";
    if (!backup.Cleanup()) {
        std::cerr << "BackupComplete failed.\n";
    }

    std::cout << "Backup finished.\n";
    return 0;
}
