#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <commctrl.h>

#pragma comment(lib, "comctl32.lib")
HWND hProcessList, hDllPathEdit, hStatusBar;
std::vector<DWORD> processIds;
std::vector<std::wstring> processNames;
wchar_t selectedDllPath[MAX_PATH] = L"";

// process id
std::wstring GetProcessName(DWORD processId) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return L"Unknown";
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (pe.th32ProcessID == processId) {
                CloseHandle(hSnapshot);
                return pe.szExeFile;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return L"Unknown";
}

// process list
void RefreshProcessList() {
    processIds.clear();
    processNames.clear();
    SendMessage(hProcessList, LB_RESETCONTENT, 0, 0);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe)) {
        do {
            processIds.push_back(pe.th32ProcessID);
            processNames.push_back(pe.szExeFile);
            std::wstring display = std::wstring(pe.szExeFile) + L" (PID: " + std::to_wstring(pe.th32ProcessID) + L")";
            SendMessageW(hProcessList, LB_ADDSTRING, 0, (LPARAM)display.c_str());
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
}

// inject into process
bool InjectDll(DWORD processId, const wchar_t* dllPath) {
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE,
        processId
    );
    if (!hProcess) {
        DWORD error = GetLastError();
        if (error == ERROR_ACCESS_DENIED) {
            MessageBox(NULL, L"Access Denied! Run as Administrator.", L"Error", MB_ICONERROR);
        }
        return false;
    }
    size_t pathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMemory) {
        CloseHandle(hProcess);
        return false;
    }
    if (!WriteProcessMemory(hProcess, remoteMemory, dllPath, pathSize, NULL)) {
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, remoteMemory, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return true;
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE: {
        CreateWindowW(L"STATIC", L"DLL File:", WS_VISIBLE | WS_CHILD, 10, 10, 80, 20, hwnd, NULL, NULL, NULL);
        hDllPathEdit = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_READONLY, 90, 10, 300, 25, hwnd, NULL, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Browse...", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 400, 10, 80, 25, hwnd, (HMENU)1, NULL, NULL);
        CreateWindowW(L"STATIC", L"Running Processes:", WS_VISIBLE | WS_CHILD, 10, 45, 120, 20, hwnd, NULL, NULL, NULL);
        hProcessList = CreateWindowW(L"LISTBOX", NULL, WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL | LBS_NOTIFY, 10, 65, 470, 250, hwnd, NULL, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Refresh", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 10, 325, 100, 30, hwnd, (HMENU)2, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Inject DLL", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 120, 325, 100, 30, hwnd, (HMENU)3, NULL, NULL);
        RefreshProcessList();
        break;
    }
    case WM_COMMAND: {
        if (LOWORD(wParam) == 1) {
            OPENFILENAMEW ofn = { 0 };
            wchar_t fileName[MAX_PATH] = { 0 };
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = hwnd;
            ofn.lpstrFilter = L"DLL Files\0*.dll\0All Files\0*.*\0";
            ofn.lpstrFile = fileName;
            ofn.nMaxFile = MAX_PATH;
            ofn.Flags = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
            if (GetOpenFileNameW(&ofn)) {
                wcscpy_s(selectedDllPath, fileName);
                SetWindowTextW(hDllPathEdit, fileName);
            }
        }
        else if (LOWORD(wParam) == 2) {
            RefreshProcessList();
        }
        else if (LOWORD(wParam) == 3) {
            if (wcslen(selectedDllPath) == 0) {
                MessageBox(hwnd, L"Please select a DLL file first!", L"Error", MB_ICONWARNING);
                break;
            }
            int selectedIndex = (int)SendMessage(hProcessList, LB_GETCURSEL, 0, 0);
            if (selectedIndex == LB_ERR) {
                MessageBox(hwnd, L"Please select a process!", L"Error", MB_ICONWARNING);
                break;
            }
            DWORD targetPid = processIds[selectedIndex];
            std::wstring targetName = processNames[selectedIndex];
            if (InjectDll(targetPid, selectedDllPath)) {
                std::wstring successMsg = L"Successfully injected into:\n";
                successMsg += targetName + L" (PID: " + std::to_wstring(targetPid) + L")";
                MessageBox(hwnd, successMsg.c_str(), L"Injection Successful", MB_ICONINFORMATION);
            }
            else {
                std::wstring failMsg = L"Failed to inject into:\n";
                failMsg += targetName + L" (PID: " + std::to_wstring(targetPid) + L")\n\n";
                failMsg += L"Possible reason:\n";
                failMsg += L"- Run as Administrator\n";
                failMsg += L"- Antivirus blocking\n";
                failMsg += L"- Process protected\n";
                failMsg += L"- Wrong architecture (32-bit vs 64-bit)";
                MessageBox(hwnd, failMsg.c_str(), L"Injection Failed", MB_ICONERROR);
            }
        }
        break;
    }
    case WM_SIZE: {
        break;
    }
    case WM_DESTROY: {
        PostQuitMessage(0);
        break;
    }
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icex);

    const wchar_t CLASS_NAME[] = L"DLLInjectorClass";
    WNDCLASSW wc = { 0 };
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassW(&wc);

    // create window
    HWND hwnd = CreateWindowExW(
        0,
        CLASS_NAME,
        L"DLL Injector",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 520, 420,
        NULL,
        NULL,
        hInstance,
        NULL
    );

    if (!hwnd) return 1;
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg = { 0 };
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}