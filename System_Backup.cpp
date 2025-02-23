#include <windows.h>
#include <winioctl.h>    // For IOCTL_DISK_GET_DRIVE_LAYOUT_EX
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
#include <vector>
#include <locale>
#include <codecvt>

// Link with vssapi.lib (MSVC will link additional Windows libraries automatically)
#pragma comment(lib, "vssapi.lib")

// Helper macro for HRESULT error checking and logging with COM error details
#define CHECK_HR_AND_FAIL(hr, msg) \
    if (FAILED(hr)) { \
        _com_error err(hr); \
        std::wcerr << msg << " (hr=0x" << std::hex << hr << "): " << err.ErrorMessage() << "\n"; \
        return false; \
    }

// Helper function to get a descriptive error message from GetLastError()
std::wstring GetLastErrorAsString()
{
    DWORD errorMessageID = GetLastError();
    if (errorMessageID == 0)
        return std::wstring(); //No error message has been recorded

    LPWSTR messageBuffer = nullptr;
    size_t size = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&messageBuffer, 0, NULL);

    std::wstring message(messageBuffer, size);
    LocalFree(messageBuffer); //Free the buffer allocated by the system
    return message;
}

//
// VSSFileLevelBackup uses VSS to create a snapshot of a volume,
// then maps the snapshot’s device to a drive letter (via subst) so that
// standard file copy routines (using std::filesystem) can copy files.
//
class VSSFileLevelBackup {
private:
    IVssBackupComponents* backupComponents = nullptr;
    VSS_ID snapshotSetId = GUID_NULL;
    VSS_ID snapshotId = GUID_NULL;
    std::wstring sourceDrive;
    std::wstring destFolder;
    wchar_t mappedDriveLetter = 0; // Store the mapped drive letter

public:
    VSSFileLevelBackup(const std::wstring& source, const std::wstring& destination)
        : sourceDrive(source), destFolder(destination) {
    }

    ~VSSFileLevelBackup() {
        CleanupSubstDrive(); // Ensure subst drive is removed on destruction
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
        CHECK_HR_AND_FAIL(hr, "Failed to initialize for backup");

        hr = backupComponents->SetBackupState(true, true, VSS_BT_FULL, false);
        CHECK_HR_AND_FAIL(hr, "Failed to set backup state");

        return true;
    }

    bool CreateSnapshot() {
        HRESULT hr = backupComponents->StartSnapshotSet(&snapshotSetId);
        CHECK_HR_AND_FAIL(hr, "Failed to start snapshot set");

        hr = backupComponents->AddToSnapshotSet(const_cast<LPWSTR>(sourceDrive.c_str()), GUID_NULL, &snapshotId);
        CHECK_HR_AND_FAIL(hr, "Failed to add volume to snapshot set");

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
        VSS_SNAPSHOT_PROP snapProp;
        ZeroMemory(&snapProp, sizeof(snapProp));

        HRESULT hr = backupComponents->GetSnapshotProperties(snapshotId, &snapProp);
        if (FAILED(hr)) {
            std::wcerr << "Failed to get snapshot properties (hr=0x" << std::hex << hr << ")\n";
            return false;
        }

        std::wstring shadowPath = snapProp.m_pwszSnapshotDeviceObject;
        if (shadowPath.empty()) {
            std::wcerr << "Snapshot device path is empty.\n";
            VssFreeSnapshotProperties(&snapProp);
            return false;
        }
        std::wcout << L"Shadow copy device: " << shadowPath << std::endl;

        mappedDriveLetter = FindAvailableDriveLetter();
        if (mappedDriveLetter == 0) {
            std::wcerr << L"No available drive letter found for mapping snapshot.\n";
            VssFreeSnapshotProperties(&snapProp);
            return false;
        }
        std::wstring substDriveStr;
        substDriveStr += mappedDriveLetter;
        substDriveStr += L":";


        // Use the subst command to map the shadow copy device to an available drive letter
        std::wstring substCommand = L"subst " + substDriveStr + L" \"" + shadowPath + L"\"";
        int substResult = _wsystem(substCommand.c_str());
        if (substResult != 0) {
            std::wcerr << L"Failed to map shadow copy to drive " << substDriveStr << L" (subst returned " << substResult << L")\n";
            VssFreeSnapshotProperties(&snapProp);
            return false;
        }
        std::wstring mappedPath = substDriveStr + L"\\";
        std::wcout << L"Mapped shadow copy to drive " << substDriveStr << L" (" << mappedPath << L")\n";

        // Enumerate the contents of the mapped drive to check accessibility and debug
        try {
            auto dirIter = std::filesystem::directory_iterator(mappedPath);
            size_t count = 0;
            std::wcout << L"Listing first 10 items in mapped drive " << mappedPath << ":" << std::endl;
            int itemCounter = 0;
            for (auto& entry : dirIter) {
                std::wcout << L"  " << entry.path().filename().wstring() << std::endl;
                ++count;
                if (++itemCounter >= 10) break; // List only first 10 for brevity in output
            }
            std::wcout << L"Found " << count << L" items in " << mappedPath << std::endl;
            if (count == 0) {
                std::wcerr << L"No files or folders detected at " << mappedPath << L". Possible issue with snapshot content or mapping.\n";
            }
        }
        catch (const std::filesystem::filesystem_error& ex) {
            std::cerr << "Error enumerating directory " << std::filesystem::path(mappedPath).string()
                << ": " << ex.what() << "\n";
            CleanupSubstDrive(); // Attempt to remove subst mapping in case of error
            VssFreeSnapshotProperties(&snapProp);
            return false;
        }

        // Perform the recursive copy using std::filesystem
        try {
            std::filesystem::create_directories(destFolder);
            std::filesystem::copy(mappedPath, destFolder,
                std::filesystem::copy_options::recursive |
                std::filesystem::copy_options::overwrite_existing);
            std::wcout << L"File-level backup completed from " << mappedPath
                << L" to " << destFolder << std::endl;
        }
        catch (const std::filesystem::filesystem_error& ex) {
            std::cerr << "Filesystem copy error from " << std::filesystem::path(mappedPath).string() << " to " << std::filesystem::path(destFolder).string() << ": " << ex.what() << "\n";
            CleanupSubstDrive();
            VssFreeSnapshotProperties(&snapProp);
            return false;
        }

        CleanupSubstDrive();
        VssFreeSnapshotProperties(&snapProp);
        return true;
    }

    bool Cleanup() {
        if (backupComponents) {
            IVssAsync* pAsync = nullptr;
            HRESULT hr = backupComponents->BackupComplete(&pAsync);
            if (FAILED(hr)) {
                std::wcerr << "BackupComplete failed (hr=0x" << std::hex << hr << ")\n";
                return false;
            }
            if (pAsync) {
                hr = pAsync->Wait();
                pAsync->Release();
                if (FAILED(hr)) {
                    std::wcerr << "BackupComplete Wait() failed (hr=0x" << std::hex << hr << ")\n";
                    return false;
                }
            }
        }
        return true;
    }

private:
    wchar_t FindAvailableDriveLetter() {
        DWORD drivesMask = GetLogicalDrives();
        for (wchar_t letter = L'C'; letter <= L'Z'; ++letter) {
            if (!(drivesMask & (1 << (letter - L'A')))) {
                return letter;
            }
        }
        return 0; // No available drive letter found
    }

    void CleanupSubstDrive() {
        if (mappedDriveLetter != 0) {
            std::wstring substDriveStr;
            substDriveStr += mappedDriveLetter;
            substDriveStr += L":";
            std::wstring substCommand = L"subst " + substDriveStr + L" /d";
            if (_wsystem(substCommand.c_str()) != 0) {
                std::wcerr << L"Failed to remove subst mapping for drive " << substDriveStr << L"\n";
            }
            mappedDriveLetter = 0; // Reset drive letter
        }
    }
};

//
// CapturePhysicalDriveMetadata reads low-level disk metadata from a specified physical drive.
// It captures a boot record (first 4KB) and the drive's partition layout using IOCTL_DISK_GET_DRIVE_LAYOUT_EX.
// Both results are written as binary files in the destination folder.
//
bool CapturePhysicalDriveMetadata(int driveNumber, const std::wstring& destFolder) {
    std::wstring drivePath = L"\\\\.\\PhysicalDrive" + std::to_wstring(driveNumber);
    HANDLE hDrive = CreateFileW(drivePath.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_EXISTING, 0, NULL);
    if (hDrive == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Failed to open " << drivePath << L" (error=0x"
            << std::hex << GetLastError() << L"): " << GetLastErrorAsString() << "\n";
        return false;
    }

    const DWORD BOOT_RECORD_SIZE = 4096;
    std::unique_ptr<BYTE[]> bootRecord(new BYTE[BOOT_RECORD_SIZE]);
    DWORD bytesRead = 0;
    if (!ReadFile(hDrive, bootRecord.get(), BOOT_RECORD_SIZE, &bytesRead, NULL)) {
        std::wcerr << L"ReadFile for boot record failed (error=0x"
            << std::hex << GetLastError() << L"): " << GetLastErrorAsString() << "\n";
        CloseHandle(hDrive);
        return false;
    }

    std::filesystem::path bootPath = std::filesystem::path(destFolder) / L"boot_record.bin";
    try {
        std::ofstream bootFile(bootPath, std::ios::binary);
        if (!bootFile) {
            std::wcerr << L"Failed to open " << bootPath.wstring() << L" for writing.\n";
            CloseHandle(hDrive);
            return false;
        }
        bootFile.write(reinterpret_cast<char*>(bootRecord.get()), bytesRead);
        bootFile.close();
        std::wcout << L"Boot record (" << bytesRead << L" bytes) written to "
            << bootPath.wstring() << std::endl;
    }
    catch (const std::exception& ex) {
        std::wcerr << L"Exception writing boot record: " << ex.what() << std::endl;
        CloseHandle(hDrive);
        return false;
    }

    DWORD outSize = sizeof(DRIVE_LAYOUT_INFORMATION_EX) + 128 * sizeof(PARTITION_INFORMATION_EX);
    std::unique_ptr<BYTE[]> layoutBuffer(new BYTE[outSize]);
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(hDrive, IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
        NULL, 0, layoutBuffer.get(), outSize, &bytesReturned, NULL)) {
        std::wcerr << L"IOCTL_DISK_GET_DRIVE_LAYOUT_EX failed (error=0x"
            << std::hex << GetLastError() << L"): " << GetLastErrorAsString() << "\n";
        CloseHandle(hDrive);
        return false;
    }

    std::filesystem::path layoutPath = std::filesystem::path(destFolder) / L"drive_layout.bin";
    try {
        std::ofstream layoutFile(layoutPath, std::ios::binary);
        if (!layoutFile) {
            std::wcerr << L"Failed to open " << layoutPath.wstring() << L" for writing.\n";
            CloseHandle(hDrive);
            return false;
        }
        layoutFile.write(reinterpret_cast<char*>(layoutBuffer.get()), bytesReturned);
        layoutFile.close();
        std::wcout << L"Drive layout (" << bytesReturned << L" bytes) written to "
            << layoutPath.wstring() << std::endl;
    }
    catch (const std::exception& ex) {
        std::wcerr << L"Exception writing drive layout: " << ex.what() << std::endl;
        CloseHandle(hDrive);
        return false;
    }

    CloseHandle(hDrive);
    return true;
}


//
// Check if running as administrator.
static bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (!AllocateAndInitializeSid(&ntAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup))
    {
        // std::cerr << "Failed to initialize SID: " << GetLastErrorAsString() << "\n";
        std::cerr << "Failed to initialize SID: " << std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(GetLastErrorAsString()) << "\n";

        return false;
    }

    if (!CheckTokenMembership(NULL, adminGroup, &isAdmin)) {
        FreeSid(adminGroup);
        // std::cerr << "Failed to check token membership: " << GetLastErrorAsString() << "\n";

        std::cerr << "Failed to check token membership: " << std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(GetLastErrorAsString()) << "\n";
        return false;
    }

    FreeSid(adminGroup);
    return (isAdmin == TRUE);
}

//
// Main: Performs a VSS file-level backup and captures disk metadata.
//
int wmain() {
    if (!IsRunningAsAdmin()) {
        std::wcerr << L"This program requires administrator privileges.\n";
        return 1;
    }

    std::wstring volume;
    std::wstring destFolder;
    std::wstring driveNumStr;

    std::wcout << L"Enter volume to snapshot (e.g., C:\\): ";
    std::getline(std::wcin, volume);
    if (volume.empty()) {
        volume = L"C:\\";
    }

    std::wcout << L"Enter destination folder for backup (e.g., D:\\Backup\\SystemImage): ";
    std::getline(std::wcin, destFolder);
    if (destFolder.empty()) {
        std::wcerr << L"No destination folder provided.\n";
        return 1;
    }

    std::wcout << L"Enter physical drive number for metadata capture (e.g., 0 for \\\\.\\PhysicalDrive0): ";
    std::getline(std::wcin, driveNumStr);
    int driveNumber = 0;
    if (!driveNumStr.empty()) {
        try {
            driveNumber = std::stoi(driveNumStr);
        }
        catch (...) {
            std::wcerr << L"Invalid drive number. Defaulting to 0.\n";
            driveNumber = 0;
        }
    }


    // Perform VSS file-level backup.
    VSSFileLevelBackup backup(volume, destFolder);
    if (!backup.Initialize()) {
        std::cerr << "VSS Initialization failed.\n";
        return 1;
    }

    std::cout << "Creating VSS snapshot...\n";
    if (!backup.CreateSnapshot()) {
        std::cerr << "CreateSnapshot failed.\n";
        return 1;
    }

    std::cout << "Performing file-level backup...\n";
    if (!backup.FileLevelBackup()) {
        std::cerr << "FileLevelBackup failed.\n";
        return 1;
    }

    std::cout << "Cleaning up VSS snapshot...\n";
    if (!backup.Cleanup()) {
        std::cerr << "BackupComplete failed.\n";
        return 1;
    }

    // Capture additional disk metadata (boot record and partition layout)
    std::cout << "Capturing physical drive metadata...\n";
    if (!CapturePhysicalDriveMetadata(driveNumber, destFolder)) {
        std::cerr << "Physical drive metadata capture failed.\n";
        return 1;
    }

    std::cout << "Backup finished.\n";
    return 0;


    // Replace the problematic line with the following code
    std::wcerr << L"Failed to check token membership: " << std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t>().to_bytes(GetLastErrorAsString()) << L"\n";
}