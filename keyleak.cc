#include "keyleak.h"
#include <Windows.h>
#include <Psapi.h>
#include <basetsd.h>
#include <corecrt_wstdio.h>
#include <debugapi.h>
#include <errhandlingapi.h>
#include <handleapi.h>
#include <interlockedapi.h>
#include <memoryapi.h>
#include <minwinbase.h>
#include <minwindef.h>
#include <processthreadsapi.h>
#include <stdio.h>
#include <tchar.h>
#include <vcruntime_string.h>
#include <winbase.h>
#include <windef.h>
#include <winnt.h>

static void PrintCTX(cipher_ctx *ctx) {
  printf("code_ctx info\n");
  printf("\tderive_key:\t%d\n", ctx->derive_key);
  printf("\tpass_sz:\t%d\n", ctx->pass_sz);
  printf("\tkey:\t");
  putchar('\t');
  for (int i = 0; i < 0x20; i++) {
    printf("%02hhx", ctx->key[i]);
  }
  putchar('\n');
  printf("\thmac_key:\t");
  putchar('\t');
  for (int i = 0; i < 0x20; i++) {
    printf("%02hhx", ctx->hmac_key[i]);
  }
  putchar('\n');

  printf("\tkeyspec:\t%s\n", ctx->keyspec);
}

const int MAX_PROCESS = 65536;
const char *sqlcipher_page_cipher_replaced_value = "\x55";
const char *INT3 = "\xCC";
const int keyspec_sz = 0x63;
const int key_sz = 0x20;

DWORD GetWXPid() {
  DWORD *aProcesses;
  DWORD cbNeeded, cProcesses;
  DWORD wxPid = 0;

  aProcesses = new DWORD[MAX_PROCESS];

  if (!EnumProcesses(aProcesses, MAX_PROCESS * sizeof(DWORD), &cbNeeded)) {
    return 1;
  }

  cProcesses = cbNeeded / sizeof(DWORD);

  for (int i = 0; i < cProcesses; i++) {
    if (aProcesses[i] != 0) {
      TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
      HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                    false, aProcesses[i]);
      if (NULL != hProcess) {
        HMODULE hMod;
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
          GetModuleBaseName(hProcess, hMod, szProcessName,
                            sizeof(szProcessName) / sizeof(TCHAR));
        }
        if (_tcsicmp(szProcessName, TEXT("WeChat.exe")) == 0) {
          wxPid = aProcesses[i];
          break;
        }
      }
      CloseHandle(hProcess);
    }
  }

  delete[] aProcesses;
  return wxPid;
}

SIZE_T GetWeChatWinDLLBaseAddress(int wxPid) {
  HMODULE hMods[1024];
  HANDLE hProcess;
  DWORD cbNeeded;

  hProcess =
      OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, wxPid);

  if (NULL == hProcess) {
    fprintf(stderr, "OpenProcess failed: %lu\n", GetLastError());
    return 0;
  }

  if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
    for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
      TCHAR szModName[MAX_PATH];
      if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
                              sizeof(szModName) / sizeof(TCHAR))) {
        if (_tcsstr(szModName, TEXT("WeChatWin.dll")) != 0) {
          CloseHandle(hProcess);
          return (SIZE_T)hMods[i];
        }
      }
    }
  }

  CloseHandle(hProcess);
  return 0;
}

struct cipher_ctx *GetCipherCtx(HANDLE process, LPVOID ctx_ptr) {
  struct cipher_ctx *ctx = new struct cipher_ctx;
  SIZE_T readBytes = 0;

  if (NULL == ReadProcessMemory(process, (LPCVOID)(ctx_ptr), (LPVOID)ctx,
                                sizeof(cipher_ctx), (SIZE_T *)&readBytes)) {
    fprintf(stderr, "[-] ReadProcessMemory failed: %lu\n", GetLastError());
    exit(-1);
  }

  if (ctx->derive_key == 1) {
    // only pass_sz and pass are valid, and the key and hmac_key are
    // null memory, keyspec is nullptr here we only read the pass from
    // the process
    unsigned char *pass = new unsigned char[ctx->pass_sz];
    if (NULL == ReadProcessMemory(process, (LPCVOID)ctx->pass, (LPVOID)pass,
                                  (SIZE_T)ctx->pass_sz, (SIZE_T *)&readBytes)) {
      fprintf(stderr, "[-] ReadProcessMemory failed: %lu\n", GetLastError());
      exit(-1);
    }
    ctx->pass = pass;
  } else {
    // read the key, hmac_key and keyspec from the process
    unsigned char *key = new unsigned char[key_sz + 1];
    unsigned char *hmac_key = new unsigned char[key_sz + 1];
    char *keyspec = new char[keyspec_sz + 1];
    memset(key, 0, key_sz + 1);
    memset(hmac_key, 0, key_sz + 1);
    memset(keyspec, 0, keyspec_sz + 1);

    if (NULL == ReadProcessMemory(process, (LPCVOID)ctx->key, (LPVOID)key,
                                  (SIZE_T)key_sz, (SIZE_T *)&readBytes)) {
      fprintf(stderr, "[-] ReadProcessMemory key failed: %lu\n",
              GetLastError());
      exit(-1);
    }

    if (NULL == ReadProcessMemory(process, (LPCVOID)ctx->hmac_key,
                                  (LPVOID)hmac_key, (SIZE_T)key_sz,
                                  (SIZE_T *)&readBytes)) {
      fprintf(stderr, "[-] ReadProcessMemory hmac_key failed: %lu\n",
              GetLastError());
      exit(-1);
    }

    if (NULL == ReadProcessMemory(process, (LPCVOID)ctx->keyspec,
                                  (LPVOID)keyspec, (SIZE_T)keyspec_sz,
                                  (SIZE_T *)&readBytes)) {
      fprintf(stderr, "[-] ReadProcessMemory keyspec failed: %lu\n",
              GetLastError());
      exit(-1);
    }

    ctx->key = key;
    ctx->hmac_key = hmac_key;
    ctx->keyspec = keyspec;
    ctx->pass = nullptr;
  }

  return ctx;
}

struct cipher_ctx *DebugWX(int wxPid, const LPVOID sqlcipher_page_cipher) {

  HANDLE wxProcess;
  struct cipher_ctx *ret = nullptr;
  wxProcess = OpenProcess(PROCESS_ALL_ACCESS, false, wxPid);
  if (NULL == wxProcess) {
    fprintf(stderr, "[-] OpenProcess with PROCESS_ALL_ACCESS failed: %lu\n",
            GetLastError());
    exit(-1);
  }

  // attach to WeChat.exe
  if (false == DebugActiveProcess(wxPid)) {
    fprintf(stderr, "[-] DebugActiveProcess failed, error code %lu\n",
            GetLastError());
    exit(-1);
  }

  // write the 0xCC to the sqlcipher_page_cipher
  SIZE_T bytesWritten;
  if (NULL == WriteProcessMemory(wxProcess, sqlcipher_page_cipher,
                                 (LPCVOID)INT3, 1, &bytesWritten)) {
    fprintf(stderr, "[-] WriteProcessMemory failed: %lu\n", GetLastError());
    exit(-1);
  }

  BOOL waitEvent = true;
  while (waitEvent) {
    DEBUG_EVENT debugInfo;
    waitEvent = WaitForDebugEvent(&debugInfo, INFINITE);

    if (debugInfo.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {

      if (debugInfo.u.Exception.ExceptionRecord.ExceptionCode ==
          EXCEPTION_BREAKPOINT) {
        // get ESP
        CONTEXT integerContext;
        integerContext.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;

        HANDLE wxThread =
            OpenThread(THREAD_ALL_ACCESS, false, debugInfo.dwThreadId);
        if (NULL == wxThread) {
          fprintf(stderr, "[-] OpenThread failed: %lu\n", GetLastError());
          exit(-1);
        }

        if (NULL != GetThreadContext(wxThread, &integerContext)) {
          if (integerContext.Eip == (DWORD)sqlcipher_page_cipher + 1) {
            SIZE_T codecCtx = integerContext.Ecx;
            DWORD readBytes = 0;

            fprintf(stderr, "[+] got codeCtx address: 0x%08lx\n", codecCtx);

            // read_ctx *(codecCtx + 0x54)
            SIZE_T read_ctx_ptr = 0;
            SIZE_T write_ctx_ptr = 0;
            if (NULL == ReadProcessMemory(wxProcess, (LPCVOID)(codecCtx + 0x54),
                                          (LPVOID)&read_ctx_ptr, sizeof(SIZE_T),
                                          (SIZE_T *)&readBytes)) {
              fprintf(stderr,
                      "[-] ReadProcessMemory failed: %lu, read %d bytes\n",
                      GetLastError(), readBytes);
              exit(-1);
            }

            fprintf(stderr, "[+] got read_ctx address: 0x%08lx\n",
                    read_ctx_ptr);

            cipher_ctx *read_ctx =
                GetCipherCtx(wxProcess, (LPVOID)read_ctx_ptr);
            PrintCTX(read_ctx);

            // replace 0xCC
            SIZE_T bytesWritten;
            if (NULL == WriteProcessMemory(
                            wxProcess, sqlcipher_page_cipher,
                            (LPCVOID)sqlcipher_page_cipher_replaced_value, 1,
                            &bytesWritten)) {
              fprintf(stderr, "[-] WriteProcessMemory failed: %lu\n",
                      GetLastError());
              exit(-1);
            }

            integerContext.Eip = integerContext.Eip - 1;
            if (NULL == SetThreadContext(wxThread, &integerContext)) {
              fprintf(stderr, "[-] SetThreadContext failed: %lu\n",
                      GetLastError());
              exit(-1);
            }
            // stop the debugging
            ContinueDebugEvent(debugInfo.dwProcessId, debugInfo.dwThreadId,
                               DBG_CONTINUE);
            DebugActiveProcessStop(wxPid);
            waitEvent = false;
            CloseHandle(wxThread);
            ret = read_ctx;
            break;
          }
        } else {
          fprintf(stderr, "[-] GetThreadContext failed: %lu, wait\n",
                  GetLastError());
        }
        CloseHandle(wxThread);
      }

    } else if (debugInfo.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
      fprintf(stderr, "[!] WeChat.exe exited\n");
      waitEvent = false;
    }

    if (true == waitEvent) {
      ContinueDebugEvent(debugInfo.dwProcessId, debugInfo.dwThreadId,
                         DBG_CONTINUE);
    }
  }

  CloseHandle(wxProcess);
  return ret;
}

struct cipher_ctx *GetWXCipherContext() {
  int wxPid = 0;
  if ((wxPid = GetWXPid()) == 0) {
    fprintf(stderr, "[-] WeChat not found\n");
    exit(-1);
  }

  // find WeChat.exe
  fprintf(stderr, "[+] WeChat found, pid = %u\n", wxPid);

  // get the WeChatWin.dll base address
  SIZE_T wxWeChatWinDLLBaseAddress = 0;
  if ((wxWeChatWinDLLBaseAddress = GetWeChatWinDLLBaseAddress(wxPid)) == 0) {
    fprintf(stderr, "[-] GetWeChatWinDLLBaseAddress failed\n");
    exit(-1);
  }

  fprintf(stderr, "[+] WeChatWin base address: 0x%08lx\n",
          wxWeChatWinDLLBaseAddress);

  LPVOID sqlcipher_page_cipher =
      (void *)(0x13D4160 + wxWeChatWinDLLBaseAddress);

  return DebugWX(wxPid, sqlcipher_page_cipher);
}