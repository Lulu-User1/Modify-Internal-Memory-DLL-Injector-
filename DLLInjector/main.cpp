#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <commctrl.h>
#pragma comment(lib, "comctl32.lib")
HWND g_listbox, g_editbox;
std::vector<DWORD> g_pids;
std::vector<std::wstring> g_pnames;
wchar_t g_dll_path[MAX_PATH] = L"";
int g_debug = 0; // not used, just here because i might need it later
std::wstring GetProcName(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return L"Unknown";
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(snap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                CloseHandle(snap);
                return pe.szExeFile;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return L"Unknown";
}
void RefreshList() {
    g_pids.clear();
    g_pnames.clear();
    SendMessage(g_listbox, LB_RESETCONTENT, 0, 0);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(snap, &pe)) {
        do {
            g_pids.push_back(pe.th32ProcessID);
            g_pnames.push_back(pe.szExeFile);
            std::wstring disp = std::wstring(pe.szExeFile) + L" (" + std::to_wstring(pe.th32ProcessID) + L")";
            SendMessageW(g_listbox, LB_ADDSTRING, 0, (LPARAM)disp.c_str());
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    // auto-select first item if there is one - saves a click
    if(g_pids.size()>0)
        SendMessage(g_listbox, LB_SETCURSEL, 0, 0);
}
bool Inject(DWORD pid, const wchar_t* dllpath) {
    HANDLE proc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    if (!proc) {
        DWORD err=GetLastError(); // might need this later
        return false;
    }
    size_t pathsize = (wcslen(dllpath) + 1) * sizeof(wchar_t);
    LPVOID remoteMem = VirtualAllocEx(proc, NULL, pathsize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        CloseHandle(proc);
        return false;
    }
    if (!WriteProcessMemory(proc, remoteMem, dllpath, pathsize, NULL)) {
        VirtualFreeEx(proc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(proc);
        return false;
    }
    // i remember reading somewhere that IsBadReadPtr is obsolete but whatever
    if(IsBadReadPtr(dllpath, pathsize)) {
        VirtualFreeEx(proc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(proc);
        return false;
    }
    LPVOID loadLib = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    HANDLE thr = CreateRemoteThread(proc, NULL, 0, (LPTHREAD_START_ROUTINE)loadLib, remoteMem, 0, NULL);
    if (!thr) {
        VirtualFreeEx(proc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(proc);
        return false;
    }
    WaitForSingleObject(thr, INFINITE);
    CloseHandle(thr);
    VirtualFreeEx(proc, remoteMem, 0, MEM_RELEASE);
    CloseHandle(proc);
    return true;
}
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        CreateWindowW(L"STATIC", L"DLL path:", WS_VISIBLE | WS_CHILD, 10, 10, 60, 20, hwnd, NULL, NULL, NULL);
        g_editbox = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_READONLY, 75, 10, 300, 25, hwnd, NULL, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Browse", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 380, 10, 70, 25, hwnd, (HMENU)1, NULL, NULL);
        CreateWindowW(L"STATIC", L"Processes:", WS_VISIBLE | WS_CHILD, 10, 45, 70, 20, hwnd, NULL, NULL, NULL);
        g_listbox = CreateWindowW(L"LISTBOX", NULL, WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL | LBS_NOTIFY, 10, 65, 440, 250, hwnd, NULL, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Refresh", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 10, 325, 70, 30, hwnd, (HMENU)2, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Inject", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 90, 325, 70, 30, hwnd, (HMENU)3, NULL, NULL);
        RefreshList();
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
                wcscpy_s(g_dll_path, fileName);
                SetWindowTextW(g_editbox, fileName);
            }
        }
        else if (LOWORD(wParam) == 2) {
            RefreshList();
        }
        else if (LOWORD(wParam) == 3) {
            if (wcslen(g_dll_path) == 0) {
                MessageBox(hwnd, L"Select a DLL first.", L"Error", MB_ICONWARNING);
                break;
            }
            int sel = (int)SendMessage(g_listbox, LB_GETCURSEL, 0, 0);
            if (sel == LB_ERR) {
                MessageBox(hwnd, L"Select a process.", L"Error", MB_ICONWARNING);
                break;
            }
            DWORD pid = g_pids[sel];
            std::wstring name = g_pnames[sel];
            if (Inject(pid, g_dll_path)) {
                std::wstring msg = L"Injected into:\n" + name + L" (" + std::to_wstring(pid) + L")";
                MessageBox(hwnd, msg.c_str(), L"Success", MB_ICONINFORMATION);
            }
            else {
                std::wstring msg = L"Failed:\n" + name + L" (" + std::to_wstring(pid) + L")\n";
                msg += L"\nPossible: admin rights, antivirus, protected process, bitness mismatch.";
                MessageBox(hwnd, msg.c_str(), L"Failure", MB_ICONERROR);
            }
        }
        break;
    }
    case WM_DESTROY: {
        PostQuitMessage(0);
        break;
    }
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icex);
    const wchar_t CLASS_NAME[] = L"DLLInjectorClass";
    WNDCLASSW wc = { 0 };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassW(&wc);
    HWND hwnd = CreateWindowExW(
        0,
        CLASS_NAME,
        L"DLL Injector",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 480, 400,
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
