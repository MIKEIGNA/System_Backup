#include <windows.h>
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>
#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>
#include <comdef.h>
#include <sstream>
#include <iomanip>
#include <ctime>

#pragma comment(lib, "vssapi.lib")

// Helper function to get formatted timestamp
std::wstring GetTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);
    std::wstringstream ss;
    ss << std::put_time(std::localtime(&now_c), L"%Y%m%d_%H%M%S");
    return ss.str();
}

// Helper function to log errors
void LogError(const std::wstring& logFile, const std::wstring& message) {
    std::wofstream log(logFile, std::ios::app);
    if (log.is_open()) {
        log << GetTimestamp() << L" ERROR: " << message << std::endl;
        log.close();
    }
    std::wcerr << message << std::endl;
}

// Helper function to log info
void LogInfo(const std::wstring& logFile, const std::wstring& message) {
    std::wofstream log(logFile, std::ios::app);
    if (log.is_open()) {
        log << GetTimestamp() << L" INFO: " << message << std::endl;
        log.close();
    }
    std::wcout << message << std::endl;
}

class SystemImageBackup {
private:
    IVssBackupComponents* backupComponents;
    VSS_ID snapshotSetId;
    std::wstring sourceDrive;
    std::wstring destPath;
    std::wstring logFile;

public:
    SystemImageBackup(const std::wstring& source, const std::wstring& destination)
        : backupComponents(nullptr), sourceDrive(source), destPath(destination) {
        // Create log file in destination directory
        logFile = destPath + L"\\backup_log_" + GetTimestamp() + L".txt";
    }

    ~SystemImageBackup() {
        if (backupComponents) {
            backupComponents->Release();
        }
        CoUninitialize();
    }

    bool Initialize() {
        LogInfo(logFile, L"Initializing backup components...");

        HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
        if (FAILED(hr)) {
            LogError(logFile, L"Failed to initialize COM: 0x" + std::to_wstring(hr));
            return false;
        }

        hr = CreateVssBackupComponents(&backupComponents);
        if (FAILED(hr)) {
            LogError(logFile, L"Failed to create backup components: 0x" + std::to_wstring(hr));
            return false;
        }

        hr = backupComponents->InitializeForBackup();
        if (FAILED(hr)) {
            LogError(logFile, L"Failed to initialize for backup: 0x" + std::to_wstring(hr));
            return false;
        }

        hr = backupComponents->SetContext(VSS_CTX_BACKUP);
        if (FAILED(hr)) {
            LogError(logFile, L"Failed to set backup context: 0x" + std::to_wstring(hr));
            return false;
        }

        LogInfo(logFile, L"Initialization successful");
        return true;
    }

    bool CreateSnapshot() {
        LogInfo(logFile, L"Creating VSS snapshot...");

        HRESULT hr = backupComponents->StartSnapshotSet(&snapshotSetId);
        if (FAILED(hr)) {
            LogError(logFile, L"Failed to start snapshot set: 0x" + std::to_wstring(hr));
            return false;
        }

        VSS_ID snapshotId;
        hr = backupComponents->AddToSnapshotSet((VSS_PWSZ)sourceDrive.c_str(), GUID_NULL, &snapshotId);
        if (FAILED(hr)) {
            LogError(logFile, L"Failed to add volume to snapshot set: 0x" + std::to_wstring(hr));
            return false;
        }

        LogInfo(logFile, L"Preparing for backup...");
        IVssAsync* async = nullptr;
        hr = backupComponents->PrepareForBackup(&async);
        if (FAILED(hr)) {
            LogError(logFile, L"PrepareForBackup failed: 0x" + std::to_wstring(hr));
            return false;
        }

        if (async) {
            hr = async->Wait();
            async->Release();
            if (FAILED(hr)) {
                LogError(logFile, L"PrepareForBackup wait failed: 0x" + std::to_wstring(hr));
                return false;
            }
        }

        LogInfo(logFile, L"Creating shadow copy...");
        IVssAsync* asyncSnapshot = nullptr;
        hr = backupComponents->DoSnapshotSet(&asyncSnapshot);
        if (FAILED(hr)) {
            LogError(logFile, L"DoSnapshotSet failed: 0x" + std::to_wstring(hr));
            return false;
        }

        if (asyncSnapshot) {
            hr = asyncSnapshot->Wait();
            asyncSnapshot->Release();
            if (FAILED(hr)) {
                LogError(logFile, L"DoSnapshotSet wait failed: 0x" + std::to_wstring(hr));
                return false;
            }
        }

        LogInfo(logFile, L"Snapshot created successfully");
        return true;
    }

    bool PerformBackup() {
        LogInfo(logFile, L"Starting backup process...");

        VSS_SNAPSHOT_PROP prop;
        HRESULT hr = backupComponents->GetSnapshotProperties(snapshotSetId, &prop);
        if (FAILED(hr)) {
            LogError(logFile, L"Failed to get snapshot properties: 0x" + std::to_wstring(hr));
            return false;
        }

        std::wstring shadowPath = prop.m_pwszSnapshotDeviceObject;
        LogInfo(logFile, L"Shadow copy device: " + shadowPath);

        try {
            // Create destination directory
            std::filesystem::create_directories(destPath);

            // Create a batch file for robocopy
            std::wstring batchPath = destPath + L"\\backup_script.bat";
            std::wofstream batchFile(batchPath);
            if (!batchFile.is_open()) {
                LogError(logFile, L"Failed to create backup script");
                return false;
            }

            // Write robocopy commands to batch file
            batchFile << L"@echo off\n";
            batchFile << L"echo Starting system backup...\n";
            batchFile << L"robocopy \"" << shadowPath << "\" \"" << destPath << L"\\System_Backup\" "
                << L"/MIR /B /R:1 /W:1 /XA:SH /COPY:DATSOU /DCOPY:DAT /MT:8 /LOG:\""
                << destPath << L"\\robocopy_log.txt\"\n";
            batchFile << L"echo Backup complete. Check robocopy_log.txt for details.\n";
            batchFile << L"pause\n";
            batchFile.close();

            // Execute the batch file
            LogInfo(logFile, L"Executing backup script...");
            std::wstring command = L"cmd.exe /c \"" + batchPath + L"\"";
            int result = _wsystem(command.c_str());

            if (result >= 8) {
                LogError(logFile, L"Robocopy encountered errors during backup. Check robocopy_log.txt for details.");
                return false;
            }

            LogInfo(logFile, L"Backup completed successfully");
        }
        catch (const std::exception& e) {
            LogError(logFile, L"Exception during backup: " + std::wstring(e.what(), e.what() + strlen(e.what())));
            return false;
        }

        VssFreeSnapshotProperties(&prop);
        return true;
    }

    bool Cleanup() {
        LogInfo(logFile, L"Starting cleanup...");

        IVssAsync* async = nullptr;
        HRESULT hr = backupComponents->BackupComplete(&async);

        if (SUCCEEDED(hr) && async) {
            hr = async->Wait();
            async->Release();
        }

        if (FAILED(hr)) {
            LogError(logFile, L"Cleanup failed: 0x" + std::to_wstring(hr));
            return false;
        }

        LogInfo(logFile, L"Cleanup completed successfully");
        return true;
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
    // Create console window to keep it open
    AllocConsole();
    SetConsoleTitle(L"System Image Backup");

    if (!IsAdmin()) {
        std::cerr << "This program requires administrator privileges.\n";
        std::cout << "Press Enter to exit...";
        std::cin.get();
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
        std::cout << "Press Enter to exit...";
        std::cin.get();
        return 1;
    }

    try {
        SystemImageBackup backup(sourceDrive, destPath);

        std::cout << "Initializing backup...\n";
        if (!backup.Initialize()) {
            std::cerr << "Initialization failed. Check the log file for details.\n";
            std::cout << "Press Enter to exit...";
            std::cin.get();
            return 1;
        }

        std::cout << "Creating snapshot...\n";
        if (!backup.CreateSnapshot()) {
            std::cerr << "Snapshot creation failed. Check the log file for details.\n";
            std::cout << "Press Enter to exit...";
            std::cin.get();
            return 1;
        }

        std::cout << "Starting backup process...\n";
        if (!backup.PerformBackup()) {
            std::cerr << "Backup failed. Check the log file for details.\n";
            std::cout << "Press Enter to exit...";
            std::cin.get();
            return 1;
        }

        std::cout << "Cleaning up...\n";
        if (!backup.Cleanup()) {
            std::cerr << "Cleanup failed. Check the log file for details.\n";
            std::cout << "Press Enter to exit...";
            std::cin.get();
            return 1;
        }

        std::cout << "Backup completed successfully!\n";
    }
    catch (const std::exception& e) {
        std::cerr << "An unexpected error occurred: " << e.what() << "\n";
    }

    std::cout << "Press Enter to exit...";
    std::cin.get();
    return 0;
}