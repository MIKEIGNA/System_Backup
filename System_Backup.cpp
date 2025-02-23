#include <windows.h>
#include <winioctl.h>       // For IOCTL_DISK_GET_LENGTH_INFO
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>
#include <iostream>
#include <string>
#include <filesystem>
#include <comdef.h>

// Link with vssapi.lib and ole32.lib, etc. as needed
#pragma comment(lib, "vssapi.lib")

// Helper macro for easy COM error checking
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
        HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
        CHECK_HR_AND_FAIL(hr, "Failed to initialize COM");

        hr = CreateVssBackupComponents(&backupComponents);
        CHECK_HR_AND_FAIL(hr, "Failed to create VSS backup components");

        hr = backupComponents->InitializeForBackup();
        CHECK_HR_AND_FAIL(hr, "Failed to InitializeForBackup");

        // We are doing a full backup
        hr = backupComponents->SetBackupState(
            /*bSelectComponents=*/true,
            /*bBackupBootableSystemState=*/true,
            VSS_BT_FULL,
            /*bPartialFileSupport=*/false
        );
        CHECK_HR_AND_FAIL(hr, "Failed to SetBackupState");

        return true;
    }

    bool CreateSnapshot() {
        // Start the snapshot set
        HRESULT hr = backupComponents->StartSnapshotSet(&snapshotSetId);
        CHECK_HR_AND_FAIL(hr, "Failed to start snapshot set");

        // Add the given volume to the snapshot set
        hr = backupComponents->AddToSnapshotSet(
            (LPWSTR)sourceDrive.c_str(),  // e.g. L"C:\\"
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

        // Create the snapshot
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
        // Retrieve snapshot properties for the actual snapshotId
        VSS_SNAPSHOT_PROP snapProp;
        ZeroMemory(&snapProp, sizeof(snapProp));

        HRESULT hr = backupComponents->GetSnapshotProperties(snapshotId, &snapProp);
        if (FAILED(hr)) {
            std::cerr << "Failed to get snapshot properties (hr=0x" << std::hex << hr << ")\n";
            return false;
        }

        // This should be something like "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX"
        std::wstring shadowPath = snapProp.m_pwszSnapshotDeviceObject;
        std::wcout << L"Shadow copy device: " << shadowPath << std::endl;

        // Open shadow copy device for read
        HANDLE hShadow = CreateFileW(
            shadowPath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );
        if (hShadow == INVALID_HANDLE_VALUE) {
            std::cerr << "Failed to open shadow device for reading.\n";
            VssFreeSnapshotProperties(&snapProp);
            return false;
        }

        // Query total length of the volume
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
            std::cerr << "IOCTL_DISK_GET_LENGTH_INFO failed.\n";
            CloseHandle(hShadow);
            VssFreeSnapshotProperties(&snapProp);
            return false;
        }

        unsigned long long totalBytes = lengthInfo.Length.QuadPart;
        std::wcout << L"Volume size: " << totalBytes << L" bytes\n";

        // Ensure the output directory exists
        std::filesystem::path outPath = imagePath;
        if (outPath.has_parent_path()) {
            std::filesystem::create_directories(outPath.parent_path());
        }

        // Open .img file for writing
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
            std::cerr << "Failed to create output image file.\n";
            CloseHandle(hShadow);
            VssFreeSnapshotProperties(&snapProp);
            return false;
        }

        // Read the shadow volume in chunks
        const DWORD BUF_SIZE = 1024 * 1024; // 1 MB per read
        std::unique_ptr<char[]> buffer(new char[BUF_SIZE]);

        LARGE_INTEGER offset;
        offset.QuadPart = 0;

        ULONGLONG bytesReadTotal = 0;
        while (bytesReadTotal < totalBytes) {
            DWORD toRead = (DWORD)std::min<ULONGLONG>(BUF_SIZE, totalBytes - bytesReadTotal);
            DWORD dwRead = 0;

            // Move file pointer on the shadow device
            if (!SetFilePointerEx(hShadow, offset, NULL, FILE_BEGIN)) {
                std::cerr << "SetFilePointerEx failed.\n";
                break;
            }

            // Read from shadow device
            BOOL ok = ReadFile(hShadow, buffer.get(), toRead, &dwRead, NULL);
            if (!ok || dwRead == 0) {
                // Reached EOF or got an error
                if (!ok) {
                    std::cerr << "ReadFile failed at offset " << offset.QuadPart << "\n";
                }
                break;
            }

            // Write to the .img file
            DWORD dwWritten = 0;
            ok = WriteFile(hImgFile, buffer.get(), dwRead, &dwWritten, NULL);
            if (!ok || dwWritten != dwRead) {
                std::cerr << "WriteFile failed at offset " << offset.QuadPart << "\n";
                break;
            }

            // Advance
            offset.QuadPart += dwRead;
            bytesReadTotal += dwRead;
        }

        std::wcout << L"Finished reading " << bytesReadTotal << L" bytes out of " << totalBytes << L"\n";

        // Cleanup
        CloseHandle(hImgFile);
        CloseHandle(hShadow);
        VssFreeSnapshotProperties(&snapProp);

        // If we read as many bytes as totalBytes, we consider it success
        return (bytesReadTotal == totalBytes);
    }

    bool Cleanup() {
        // Perform the VSS BackupComplete
        if (backupComponents) {
            IVssAsync* pAsync = nullptr;
            HRESULT hr = backupComponents->BackupComplete(&pAsync);
            if (SUCCEEDED(hr) && pAsync) {
                hr = pAsync->Wait();
                pAsync->Release();
            }
            if (FAILED(hr)) {
                std::cerr << "BackupComplete failed (hr=0x" << std::hex << hr << ")\n";
                return false;
            }
        }
        return true;
    }
};

static bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (!AllocateAndInitializeSid(
        &ntAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &adminGroup))
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
    // Require admin privileges
    if (!IsRunningAsAdmin()) {
        std::cerr << "This program requires administrator privileges.\n";
        return 1;
    }

    // Ask user for the volume to back up and the output .img file
    std::wstring volume = L"C:\\";
    std::wstring destImg;

    std::wcout << L"Enter volume to snapshot (e.g. C:\\): ";
    std::getline(std::wcin, volume);
    if (volume.empty()) {
        volume = L"C:\\";
    }

    std::wcout << L"Enter path to .img file (e.g. D:\\Backups\\MyDisk.img): ";
    std::getline(std::wcin, destImg);
    if (destImg.empty()) {
        std::wcerr << L"No destination path provided.\n";
        return 1;
    }

    // Create our backup helper
    VSSBlockLevelBackup backup(volume, destImg);

    // 1. Initialize
    if (!backup.Initialize()) {
        std::cerr << "Initialization failed.\n";
        return 1;
    }

    // 2. Create snapshot
    std::cout << "Creating snapshot...\n";
    if (!backup.CreateSnapshot()) {
        std::cerr << "CreateSnapshot failed.\n";
        return 1;
    }

    // 3. Perform block-level backup to .img
    std::cout << "Reading raw sectors from shadow copy to image...\n";
    if (!backup.BackupToImage()) {
        std::cerr << "BackupToImage failed.\n";
        // We'll still try Cleanup, but let's note the error
    }

    // 4. Cleanup
    std::cout << "Cleaning up...\n";
    if (!backup.Cleanup()) {
        std::cerr << "BackupComplete failed.\n";
    }

    std::cout << "Backup finished.\n";
    return 0;
}
