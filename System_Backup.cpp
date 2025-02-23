#include <windows.h>
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>
#include <iostream>
#include <string>
#include <filesystem>
#include <comdef.h>
#include <system_error>

// Link with vssapi.lib (and automatically, ole32.lib, etc.)
#pragma comment(lib, "vssapi.lib")

// Helper macro for HRESULT error checking
#define CHECK_HR_AND_FAIL(hr, msg) \
    if (FAILED(hr)) { \
        std::cerr << msg << " (hr=0x" << std::hex << hr << ")\n"; \
        return false; \
    }

class VSSFileLevelBackup {
private:
    IVssBackupComponents* backupComponents = nullptr;
    VSS_ID snapshotSetId = GUID_NULL;
    VSS_ID snapshotId = GUID_NULL;
    std::wstring sourceDrive;
    std::wstring destFolder;

public:
    VSSFileLevelBackup(const std::wstring& source, const std::wstring& destination)
        : sourceDrive(source), destFolder(destination) {
    }

    ~VSSFileLevelBackup() {
        if (backupComponents) {
            backupComponents->Release();
        }
        CoUninitialize();
    }

    bool Initialize() {
        // Initialize COM for multi-threaded concurrency.
        HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
        CHECK_HR_AND_FAIL(hr, "Failed to initialize COM");

        hr = CreateVssBackupComponents(&backupComponents);
        CHECK_HR_AND_FAIL(hr, "Failed to create VSS backup components");

        hr = backupComponents->InitializeForBackup();
        CHECK_HR_AND_FAIL(hr, "Failed to initialize for backup");

        // Set backup state: select components and backup bootable system state.
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
        // Start a new snapshot set.
        HRESULT hr = backupComponents->StartSnapshotSet(&snapshotSetId);
        CHECK_HR_AND_FAIL(hr, "Failed to start snapshot set");

        // Add the target volume to the snapshot set.
        hr = backupComponents->AddToSnapshotSet(
            const_cast<LPWSTR>(sourceDrive.c_str()), // e.g. L"C:\\" 
            GUID_NULL,
            &snapshotId
        );
        CHECK_HR_AND_FAIL(hr, "Failed to add volume to snapshot set");

        // Prepare for backup.
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

        // Create the snapshot.
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

    bool FileLevelBackup() {
        // Retrieve snapshot properties using the specific snapshotId.
        VSS_SNAPSHOT_PROP snapProp;
        ZeroMemory(&snapProp, sizeof(snapProp));

        HRESULT hr = backupComponents->GetSnapshotProperties(snapshotId, &snapProp);
        if (FAILED(hr)) {
            std::cerr << "Failed to get snapshot properties (hr=0x"
                << std::hex << hr << ")\n";
            return false;
        }

        // The snapshot properties include the shadow copy device path.
        std::wstring shadowPath = snapProp.m_pwszSnapshotDeviceObject;
        if (shadowPath.empty()) {
            std::cerr << "Snapshot device path is empty.\n";
            VssFreeSnapshotProperties(&snapProp);
            return false;
        }
        std::wcout << L"Shadow copy device: " << shadowPath << std::endl;

        // Use the shadow copy as the source directory.
        // Note: The shadow copy device (e.g. "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX")
        // represents the root of the volume.
        try {
            // Ensure the destination folder exists.
            std::filesystem::create_directories(destFolder);

            // Perform a recursive file copy from the shadow copy to the destination folder.
            std::filesystem::path srcPath(shadowPath);
            std::filesystem::copy(srcPath, destFolder,
                std::filesystem::copy_options::recursive |
                std::filesystem::copy_options::overwrite_existing);
        }
        catch (const std::filesystem::filesystem_error& ex) {
            std::cerr << "Filesystem copy error: " << ex.what() << "\n";
            VssFreeSnapshotProperties(&snapProp);
            return false;
        }

        VssFreeSnapshotProperties(&snapProp);
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
                    std::cerr << "BackupComplete Wait() failed (hr=0x" << std::hex << hr << ")\n";
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
    std::wstring destFolder;

    std::wcout << L"Enter volume to snapshot (e.g., C:\\): ";
    std::getline(std::wcin, volume);
    if (volume.empty()) {
        volume = L"C:\\";
    }

    std::wcout << L"Enter destination folder for file-level backup (e.g., D:\\Backup\\SystemFiles): ";
    std::getline(std::wcin, destFolder);
    if (destFolder.empty()) {
        std::wcerr << L"No destination folder provided.\n";
        return 1;
    }

    VSSFileLevelBackup backup(volume, destFolder);

    if (!backup.Initialize()) {
        std::cerr << "Initialization failed.\n";
        return 1;
    }

    std::cout << "Creating snapshot...\n";
    if (!backup.CreateSnapshot()) {
        std::cerr << "CreateSnapshot failed.\n";
        return 1;
    }

    std::cout << "Performing file-level backup...\n";
    if (!backup.FileLevelBackup()) {
        std::cerr << "FileLevelBackup failed.\n";
        // We attempt Cleanup even if the backup fails.
    }

    std::cout << "Cleaning up...\n";
    if (!backup.Cleanup()) {
        std::cerr << "BackupComplete failed.\n";
    }

    std::cout << "Backup finished.\n";
    return 0;
}
