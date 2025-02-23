#include <windows.h>
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>
#include <iostream>
#include <string>
#include <filesystem>
#include <comdef.h>

// Need to link with vssapi.lib
#pragma comment(lib, "vssapi.lib")

class VSSBackup {
private:
    IVssBackupComponents* backupComponents;
    VSS_ID snapshotSetId;
    std::wstring sourceDrive;
    std::wstring destPath;

public:
    VSSBackup(const std::wstring& source, const std::wstring& destination)
        : backupComponents(nullptr), sourceDrive(source), destPath(destination) {
    }

    ~VSSBackup() {
        if (backupComponents) {
            backupComponents->Release();
        }
        CoUninitialize();
    }

    bool Initialize() {
        // Initialize COM
        HRESULT hr = CoInitialize(NULL);
        if (FAILED(hr)) {
            std::cerr << "Failed to initialize COM\n";
            return false;
        }

        // Initialize backup components
        hr = CreateVssBackupComponents(&backupComponents);
        if (FAILED(hr)) {
            std::cerr << "Failed to create backup components\n";
            return false;
        }

        // Initialize for backup
        hr = backupComponents->InitializeForBackup();
        if (FAILED(hr)) {
            std::cerr << "Failed to initialize for backup\n";
            return false;
        }

        return true;
    }

    bool CreateSnapshot() {
        // Set backup state
        HRESULT hr = backupComponents->SetBackupState(true, true, VSS_BT_FULL, false);
        if (FAILED(hr)) {
            std::cerr << "Failed to set backup state\n";
            return false;
        }

        // Start snapshot set
        hr = backupComponents->StartSnapshotSet(&snapshotSetId);
        if (FAILED(hr)) {
            std::cerr << "Failed to start snapshot set\n";
            return false;
        }

        // Add volume to snapshot set
        VSS_ID snapshotId;
        // hr = backupComponents->AddToSnapshotSet(sourceDrive.c_str(), GUID_NULL, &snapshotId);
        hr = backupComponents->AddToSnapshotSet(&sourceDrive[0], GUID_NULL, &snapshotId);
        if (FAILED(hr)) {
            std::cerr << "Failed to add volume to snapshot set\n";
            return false;
        }

        // Prepare for backup
        IVssAsync* pAsync = nullptr;
        hr = backupComponents->PrepareForBackup(&pAsync);
        if (SUCCEEDED(hr) && pAsync) {
            hr = pAsync->Wait();
            pAsync->Release();
        }
        if (FAILED(hr)) {
            std::cerr << "Failed to prepare for backup\n";
            return false;
        }

        // Do snapshot
        IVssAsync* pAsyncSnapshot = nullptr;
        hr = backupComponents->DoSnapshotSet(&pAsyncSnapshot);
        if (SUCCEEDED(hr) && pAsyncSnapshot) {
            hr = pAsyncSnapshot->Wait();
            pAsyncSnapshot->Release();
        }
        if (FAILED(hr)) {
            std::cerr << "Failed to create snapshot\n";
            return false;
        }

        return true;
    }

    bool CopySnapshot() {
        try {
            // Get snapshot properties
            VSS_SNAPSHOT_PROP snap;
            HRESULT hr = backupComponents->GetSnapshotProperties(snapshotSetId, &snap);
            if (FAILED(hr)) {
                std::cerr << "Failed to get snapshot properties\n";
                return false;
            }

            std::wstring sourcePath = snap.m_pwszSnapshotDeviceObject;

            // Create destination if it doesn't exist
            std::filesystem::create_directories(destPath);

            // Use robocopy for reliable file copying
            std::wstring command = L"robocopy \"" + sourcePath + L"\" \"" +
                destPath + L"\" /MIR /B /R:1 /W:1";

            // Execute robocopy
            int result = _wsystem(command.c_str());

            VssFreeSnapshotProperties(&snap);

            return (result != -1);  // Return true if command executed successfully
        }
        catch (const std::exception& e) {
            std::cerr << "Error during copy: " << e.what() << "\n";
            return false;
        }
    }

    bool Cleanup() {
        if (backupComponents) {
            IVssAsync* pAsync = nullptr;
            // Call the single-parameter version of BackupComplete
            HRESULT hr = backupComponents->BackupComplete(&pAsync);
            if (SUCCEEDED(hr) && pAsync) {
                hr = pAsync->Wait();
                pAsync->Release();
            }
            if (FAILED(hr)) {
                std::cerr << "Failed to complete backup\n";
                return false;
            }
        }
        return true;
    }

};

int main() {
    // Check for administrator privileges
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (!AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        std::cerr << "Failed to initialize SID\n";
        return 1;
    }

    if (!CheckTokenMembership(NULL, adminGroup, &isAdmin)) {
        FreeSid(adminGroup);
        std::cerr << "Failed to check token membership\n";
        return 1;
    }

    FreeSid(adminGroup);

    if (!isAdmin) {
        std::cerr << "This program requires administrator privileges\n";
        return 1;
    }

    // Get source and destination paths
    std::wstring sourceDrive = L"C:\\";
    std::wstring destPath;

    std::wcout << L"Enter destination path (e.g., D:\\Backup): ";
    std::getline(std::wcin, destPath);

    // Create and initialize backup
    VSSBackup backup(sourceDrive, destPath);

    if (!backup.Initialize()) {
        std::cerr << "Failed to initialize backup\n";
        return 1;
    }

    std::cout << "Creating snapshot...\n";
    if (!backup.CreateSnapshot()) {
        std::cerr << "Failed to create snapshot\n";
        return 1;
    }

    std::cout << "Copying files...\n";
    if (!backup.CopySnapshot()) {
        std::cerr << "Failed to copy snapshot\n";
        return 1;
    }

    std::cout << "Cleaning up...\n";
    if (!backup.Cleanup()) {
        std::cerr << "Failed to cleanup\n";
        return 1;
    }

    std::cout << "Backup completed successfully!\n";
    return 0;
}