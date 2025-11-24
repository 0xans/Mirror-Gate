# Mirror Gate

![Mirror Gate](./mirror_gate.png)

## Overview

**Mirror Gate** is a Proof of Concept (PoC) written in Rust that demonstrates a process-injection technique using the Windows Console API.
It leverages `SetConsoleTitleA` and `GetConsoleTitleA` to write arbitrary data into a target process’s memory **without** using traditional primitives like `WriteProcessMemory`.

---

## Prerequisites & Constraints

To run this PoC successfully, the following requirements must be met:

### 1. Infinite Loop Address

You must provide the memory address of a “jump to self” instruction (e.g., `jmp $`, bytes `0xEB 0xFE`) located inside **kernelbase.dll**.

### 2. RWX Memory Region

The target process needs an executable **RWX** memory region to act as a temporary stack.

### 3. Thread Permissions

The injector must be able to:

* Suspend the thread
* Resume the thread
* Read and write thread context (Get/SetThreadContext)

### 4. Legacy Console

The target process **must run in the classic CMD.EXE window**.
This technique will *not work* on Windows Terminal because console title operations are handled differently.

---

## How It Works

Mirror Gate achieves a “write-what-where” primitive by:

1. Attaching to the target process’s console
2. Suspending the target thread
3. Modifying CPU registers (`RIP`, `RSP`, `RCX`) to redirect execution to `GetConsoleTitleA`
4. Using `SetConsoleTitleA` in the injector to push data into the target buffer through the shared console window title

---

## Usage

### Build

Ensure Rust is installed, then compile with:

```
cargo build --release
```

### Run

The tool requires three arguments:

```
injector.exe <PID> <TID> <LOOP_ADDRESS_HEX>
```

### Example

```
target\release\injector.exe 1234 5678 0x7ff8123456
```

