#include <windows.h>
#include <winioctl.h>       // For IOCTL_DISK_GET_DRIVE_LAYOUT_EX
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>
#include <compressapi.h>    // For compression
#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>
#include <comdef.h>
#include <memory>
#include <algorithm>

// Link with vssapi.lib and cabinet.lib for compression
#pragma comment(lib, "vssapi.lib")
#pragma comment(lib, "cabinet.lib")

// Helper macro for HRESULT error checking and logging
#define CHECK_HR_AND_FAIL(hr, msg) \
    if (FAILED(hr)) { \
        std::cerr << msg << " (hr=0x" << std::hex << hr << ")\n"; \
        return false; \
    }

// Helper macro for Win32 error checking
#define CHECK_WIN32_AND_FAIL(expr, msg) \
    if (!(expr)) { \
        std::cerr << msg << " (error=0x" << std::hex << GetLastError() << ")\n"; \
        return false; \
    }

class VSSFileLevelBackup {
private:
    IVssBackupComponents* backupComponents = nullptr;
    VSS_ID snapshotSetId = GUID_NULL;
    VSS_ID snapshotId = GUID_NULL;
    std::wstring sourceDrive;
    std::wstring destFolder;

    // Compress a single file into the compressor and write to output handle
    bool CompressFile(const std::filesystem::path& sourcePath, COMPRESSOR_HANDLE compressor, HANDLE hOutput) {
        std::ifstream inFile(sourcePath, std::ios::binary);
        if (!inFile) {
            std::cerr << "Failed to open source file: " << sourcePath.string() << "\n";
            return false;
        }

        const size_t BUFFER_SIZE = 65536;  // 64 KB buffer
        std::vector<char> inputBuffer(BUFFER_SIZE);
        std::vector<BYTE> compressedBuffer(BUFFER_SIZE * 2);  // Larger buffer for compressed data
        SIZE_T bytesCompressed;

        while (inFile.read(inputBuffer.data(), BUFFER_SIZE) || inFile.gcount() > 0) {
            SIZE_T bytesRead = static_cast<SIZE_T>(inFile.gcount());
            BOOL success = Compress(compressor, inputBuffer.data(), bytesRead,
                compressedBuffer.data(), compressedBuffer.size(), &bytesCompressed);
            if (!success && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                compressedBuffer.resize(compressedBuffer.size() * 2);
                success = Compress(compressor, inputBuffer.data(), bytesRead,
                    compressedBuffer.data(), compressedBuffer.size(), &bytesCompressed);
            }
            CHECK_WIN32_AND_FAIL(success, "Compress failed for " + sourcePath.string());

            DWORD bytesWritten;
            success = WriteFile(hOutput, compressedBuffer.data(), static_cast<DWORD>(bytesCompressed), &bytesWritten, NULL);
            CHECK_WIN32_AND_FAIL(success, "WriteFile failed for " + sourcePath.string());
        }

        inFile.close();
        return true;
    }

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
            std::cerr << "Failed to get snapshot properties (hr=0x" << std::hex << hr << ")\n";
            return false;
        }

        std::wstring shadowPath = snapProp.m_pwszSnapshotDeviceObject;
        if (shadowPath.empty()) {
            std::cerr << "Snapshot device path is empty.\n";
            VssFreeSnapshotProperties(&snapProp);
            return false;
        }
        std::wcout << L"Shadow copy device: " << shadowPath << std::endl;

        std::wstring driveLetter = L"Z:";
        if (!DefineDosDeviceW(0, driveLetter.c_str(), shadowPath.c_str())) {
            std::wcerr << L"Failed to map shadow copy to drive " << driveLetter << L" (error=0x"
                << std::hex << GetLastError() << L")\n";
            VssFreeSnapshotProperties(&snapProp);
            return false;
        }
        std::wstring mappedPath = driveLetter + L"\\";
        std::wcout << L"Mapped shadow copy to drive " << driveLetter << L" (" << mappedPath << L")\n";

        // Check snapshot contents
        size_t count = 0;
        try {
            auto dirIter = std::filesystem::directory_iterator(mappedPath);
            for (auto& entry : dirIter) {
                ++count;
                if (count <= 5) {
                    std::wcout << L"Found: " << entry.path().wstring() << L"\n";
                }
            }
            std::wcout << L"Found " << count << L" items in " << mappedPath << std::endl;
            if (count == 0) {
                std::wcerr << L"No files or folders detected at " << mappedPath << L". Snapshot may be inaccessible.\n";
            }
        }
        catch (const std::filesystem::filesystem_error& ex) {
            std::cerr << "Error enumerating directory " << std::filesystem::path(mappedPath).string()
                << ": " << ex.what() << "\n";
            DefineDosDeviceW(DDD_REMOVE_DEFINITION, driveLetter.c_str(), NULL);
            VssFreeSnapshotProperties(&snapProp);
            return false;
        }

        // Create compressed output file
        std::filesystem::path compressedPath = std::filesystem::path(destFolder) / L"system_backup.cmp";
        std::filesystem::create_directories(destFolder);
        HANDLE hOutput = CreateFileW(compressedPath.wstring().c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hOutput == INVALID_HANDLE_VALUE) {
            std::wcerr << L"Failed to create compressed file " << compressedPath.wstring() << L" (error=0x"
                << std::hex << GetLastError() << L")\n";
            DefineDosDeviceW(DDD_REMOVE_DEFINITION, driveLetter.c_str(), NULL);
            VssFreeSnapshotProperties(&snapProp);
            return false;
        }

        // Initialize compressor
        COMPRESSOR_HANDLE compressor = NULL;
        BOOL success = CreateCompressor(COMPRESS_ALGORITHM_MSZIP, NULL, &compressor);
        if (!success) {
            std::cerr << "Failed to create compressor (error=0x" << std::hex << GetLastError() << ")\n";
            CloseHandle(hOutput);
            DefineDosDeviceW(DDD_REMOVE_DEFINITION, driveLetter.c_str(), NULL);
            VssFreeSnapshotProperties(&snapProp);
            return false;
        }

        // Compress files
        try {
            size_t fileCount = 0;
            for (const auto& entry : std::filesystem::recursive_directory_iterator(mappedPath)) {
                if (entry.is_regular_file()) {
                    if (!CompressFile(entry.path(), compressor, hOutput)) {
                        CloseCompressor(compressor);
                        CloseHandle(hOutput);
                        DefineDosDeviceW(DDD_REMOVE_DEFINITION, driveLetter.c_str(), NULL);
                        VssFreeSnapshotProperties(&snapProp);
                        return false;
                    }
                    ++fileCount;
                    if (fileCount % 100 == 0) {
                        std::wcout << L"Compressed " << fileCount << L" files...\n";
                    }
                }
            }
            std::wcout << L"Total files compressed: " << fileCount << L"\n";

            // Flush remaining compressed data
            std::vector<BYTE> compressedBuffer(65536 * 2);
            SIZE_T bytesCompressed;
            success = Compress(compressor, NULL, 0, compressedBuffer.data(), compressedBuffer.size(), &bytesCompressed);
            if (!success && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                compressedBuffer.resize(compressedBuffer.size() * 2);
                success = Compress(compressor, NULL, 0, compressedBuffer.data(), compressedBuffer.size(), &bytesCompressed);
            }
            CHECK_WIN32_AND_FAIL(success, "Final Compress flush failed");

            if (bytesCompressed > 0) {
                DWORD bytesWritten;
                success = WriteFile(hOutput, compressedBuffer.data(), static_cast<DWORD>(bytesCompressed), &bytesWritten, NULL);
                CHECK_WIN32_AND_FAIL(success, "WriteFile failed for flush data");
            }
        }
        catch (const std::filesystem::filesystem_error& ex) {
            std::cerr << "Filesystem error during compression: " << ex.what() << "\n";
            CloseCompressor(compressor);
            CloseHandle(hOutput);
            DefineDosDeviceW(DDD_REMOVE_DEFINITION, driveLetter.c_str(), NULL);
            VssFreeSnapshotProperties(&snapProp);
            return false;
        }

        CloseCompressor(compressor);
        CloseHandle(hOutput);

        // Cleanup
        if (!DefineDosDeviceW(DDD_REMOVE_DEFINITION, driveLetter.c_str(), NULL)) {
            std::wcerr << L"Failed to remove mapping for drive " << driveLetter << L" (error=0x"
                << std::hex << GetLastError() << L")\n";
        }

        VssFreeSnapshotProperties(&snapProp);
        std::wcout << L"Compressed backup written to " << compressedPath.wstring() << std::endl;
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

bool CapturePhysicalDriveMetadata(int driveNumber, const std::wstring& destFolder) {
    std::wstring drivePath = L"\\\\.\\PhysicalDrive" + std::to_wstring(driveNumber);
    HANDLE hDrive = CreateFileW(drivePath.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_EXISTING, 0, NULL);
    if (hDrive == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Failed to open " << drivePath << L" (error=0x"
            << std::hex << GetLastError() << L")\n";
        return false;
    }

    const DWORD BOOT_RECORD_SIZE = 4096;
    std::unique_ptr<BYTE[]> bootRecord(new BYTE[BOOT_RECORD_SIZE]);
    DWORD bytesRead = 0;
    if (!ReadFile(hDrive, bootRecord.get(), BOOT_RECORD_SIZE, &bytesRead, NULL)) {
        std::wcerr << L"ReadFile for boot record failed (error=0x"
            << std::hex << GetLastError() << L")\n";
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
            << std::hex << GetLastError() << L")\n";
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

bool isDriveLetterAvailable(wchar_t letter) {
    DWORD drives = GetLogicalDrives();
    return (drives & (1 << (letter - L'A'))) == 0;
}

static bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (!AllocateAndInitializeSid(&ntAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
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

    if (!isDriveLetterAvailable(L'Z')) {
        std::wcerr << L"Drive letter Z is in use. Please free it or choose a different letter.\n";
        return 1;
    }

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

    std::cout << "Performing compressed file-level backup...\n";
    if (!backup.FileLevelBackup()) {
        std::cerr << "FileLevelBackup failed.\n";
        return 1;
    }

    std::cout << "Cleaning up VSS snapshot...\n";
    if (!backup.Cleanup()) {
        std::cerr << "BackupComplete failed.\n";
    }

    std::cout << "Capturing physical drive metadata...\n";
    if (!CapturePhysicalDriveMetadata(driveNumber, destFolder)) {
        std::cerr << "Physical drive metadata capture failed.\n";
    }

    std::cout << "Backup finished.\n";
    return 0;
}