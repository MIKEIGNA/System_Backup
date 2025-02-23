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

#define CHECK_HR(hr, msg) \
    if (FAILED(hr)) { \
        std::cerr << msg << " (hr=0x" << std::hex << hr << ")\n"; \
        return false; \
    }

class SystemImageBackup {
private:
    IVssBackupComponents* backupComponents;
    VSS_ID snapshotSetId;
    std::wstring sourceDrive;
    std::wstring destPath;

public:
    SystemImageBackup(const std::wstring& source, const std::wstring& destination)
        : backupComponents(nullptr), sourceDrive(source), destPath(destination) {
    }

    ~SystemImageBackup() {
        if (backupComponents) {
            backupComponents->Release();
        }
        CoUninitialize();
    }

    bool Initialize() {
        HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
        CHECK_HR(hr, "Failed to initialize COM");

        hr = CreateVssBackupComponents(&backupComponents);
        CHECK_HR(hr, "Failed to create backup components");

        hr = backupComponents->InitializeForBackup();
        CHECK_HR(hr, "Failed to initialize for backup");

        hr = backupComponents->SetContext(VSS_CTX_BACKUP);
        CHECK_HR(hr, "Failed to set backup context");

        return true;
    }

    bool CreateSnapshot() {
        HRESULT hr = backupComponents->StartSnapshotSet(&snapshotSetId);
        CHECK_HR(hr, "Failed to start snapshot set");

        VSS_ID snapshotId;
        hr = backupComponents->AddToSnapshotSet((VSS_PWSZ)sourceDrive.c_str(), GUID_NULL, &snapshotId);
        CHECK_HR(hr, "Failed to add volume to snapshot set");

        IVssAsync* async = nullptr;
        hr = backupComponents->PrepareForBackup(&async);
        CHECK_HR(hr, "Failed to prepare for backup");

        if (async) {
            hr = async->Wait();
            async->Release();
            CHECK_HR(hr, "PrepareForBackup wait failed");
        }

        std::cout << "Creating shadow copy...\n";
        IVssAsync* asyncSnapshot = nullptr;
        hr = backupComponents->DoSnapshotSet(&asyncSnapshot);
        CHECK_HR(hr, "Failed to create snapshot");

        if (asyncSnapshot) {
            hr = asyncSnapshot->Wait();
            asyncSnapshot->Release();
            CHECK_HR(hr, "DoSnapshotSet wait failed");
        }

        return true;
    }

    bool PerformBackup() {
        VSS_SNAPSHOT_PROP prop;
        HRESULT hr = backupComponents->GetSnapshotProperties(snapshotSetId, &prop);
        CHECK_HR(hr, "Failed to get snapshot properties");

        std::wstring shadowPath = prop.m_pwszSnapshotDeviceObject;
        std::wcout << L"Shadow copy device: " << shadowPath << std::endl;

        // Create destination directory if it doesn't exist
        std::filesystem::create_directories(destPath);

        // Use robocopy for reliable copying with system files
        std::wstring robocopyCmd = L"robocopy \"" + shadowPath + L"\" \"" +
            destPath + L"\" /MIR /B /R:1 /W:1 /XA:SH /COPY:DATSOU /DCOPY:DAT /MT:8";

        std::wcout << L"Starting backup using robocopy...\n";
        int result = _wsystem(robocopyCmd.c_str());

        VssFreeSnapshotProperties(&prop);

        // Robocopy returns various codes, most non-zero codes are informational
        if (result >= 8) {
            std::cerr << "Robocopy encountered errors during copy\n";
            return false;
        }

        return true;
    }

    bool Cleanup() {
        IVssAsync* async = nullptr;
        HRESULT hr = backupComponents->BackupComplete(&async);

        if (SUCCEEDED(hr) && async) {
            hr = async->Wait();
            async->Release();
        }

        return SUCCEEDED(hr);
    }
};

bool IsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (!AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        return false;
    }

    if (!CheckTokenMembership(NULL, adminGroup, &isAdmin)) {
        FreeSid(adminGroup);
        return false;
    }

    FreeSid(adminGroup);
    return isAdmin == TRUE;
}

int main() {
    if (!IsAdmin()) {
        std::cerr << "This program requires administrator privileges.\n";
        return 1;
    }

    std::wstring sourceDrive;
    std::wstring destPath;

    std::wcout << L"Enter source drive (e.g., C:\\): ";
    std::getline(std::wcin, sourceDrive);
    if (sourceDrive.empty()) sourceDrive = L"C:\\";

    std::wcout << L"Enter destination path (e.g., D:\\Backup): ";
    std::getline(std::wcin, destPath);
    if (destPath.empty()) {
        std::cerr << "Destination path is required.\n";
        return 1;
    }

    SystemImageBackup backup(sourceDrive, destPath);

    std::cout << "Initializing backup...\n";
    if (!backup.Initialize()) {
        std::cerr << "Initialization failed\n";
        return 1;
    }

    std::cout << "Creating snapshot...\n";
    if (!backup.CreateSnapshot()) {
        std::cerr << "Failed to create snapshot\n";
        return 1;
    }

    std::cout << "Copying files...\n";
    if (!backup.PerformBackup()) {
        std::cerr << "Backup failed\n";
        return 1;
    }

    std::cout << "Cleaning up...\n";
    if (!backup.Cleanup()) {
        std::cerr << "Cleanup failed\n";
        return 1;
    }

    std::cout << "Backup completed successfully!\n";
    return 0;
}