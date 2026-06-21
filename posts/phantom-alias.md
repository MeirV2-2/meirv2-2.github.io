# PhantomAlias: Module Identity Without the Module

Most in-process injection techniques die at the same checkpoint. A scanner walks the process's loaded modules, finds executable memory that doesn't belong to any of them, and asks why. Allocate private RWX, reflectively load a DLL nobody knows about, overwrite a real module's `.text` - every variant trips on the same kind of bookkeeping mismatch. Either the bytes don't match what's supposed to be there, the memory type is wrong for code, or there's a module the OS doesn't think exists.

PhantomAlias takes a different trade. Pick any legit, signed Microsoft DLL the process plausibly uses, then convince the loader's accounting that a brand-new private allocation IS a second instance of that DLL. The real one stays untouched. No bytes are overwritten anywhere, on disk or in memory. The file is never even opened.

You pay one tell at the end. We'll get to it.

> **Note on prior art.** I haven't seen this exact technique published anywhere. The primitives it composes are old - reflective loading, manual LDR splicing, growable function tables, the threadpool dispatch trick - but the specific combination (keep the real alias DLL fully untouched on disk and in memory, register a duplicate-name LDR entry with full RB tree insertion, and coexist with the original in the loader graph) is one I arrived at while trying to defeat module-integrity scanners without giving up module attribution. If you've seen this written up before or know who got there first, please reach out so I can credit it properly.

## How module attribution actually works

The Windows loader tracks loaded modules in four places that scanners care about:

1. **`PEB->Ldr`** - three doubly-linked lists (`InLoadOrderModuleList`, `InMemoryOrderModuleList`, `InInitializationOrderModuleList`) whose elements are `LDR_DATA_TABLE_ENTRY` structures, one per loaded DLL. `EnumProcessModules`, `K32GetModuleInformation`, and every in-process module walk read these. The lists are sentinel-headed and circular; the loader hands out their head pointers via `PEB->Ldr->InLoadOrderModuleList` etc.

2. **`LdrpModuleBaseAddressIndex`** - an undocumented red-black tree keyed on `DllBase`. Each `LDR_DATA_TABLE_ENTRY` carries an embedded `RTL_BALANCED_NODE` (`BaseAddressIndexNode` field, at offset `0xC8` in modern Win10/11) that the loader splices into this tree on load. `RtlPcToFileHeader` walks it to answer "which loaded module owns this IP?" in O(log n) instead of a linear scan of the PEB lists. Stack walkers call it once per frame.

3. **`NtQueryVirtualMemory(MemorySectionName)`** - kernel-side query that returns the file path backing an image or mapped section. It reads `SECTION_OBJECT_POINTERS → ControlArea → FilePointer → FileName` in the kernel. Unforgeable from user mode without driver access. Private memory has no section object at all, so the call returns `STATUS_INVALID_ADDRESS`.

4. **PE `.pdata`** - each loaded image's `IMAGE_DIRECTORY_ENTRY_EXCEPTION` data: a packed `RUNTIME_FUNCTION[]` array describing every function's `[BeginAddress, EndAddress)` range and a pointer to its `UNWIND_INFO`. Used by `RtlVirtualUnwind` for SEH and stack walking, and by every cross-process stack walker (System Informer, dbghelp's `StackWalkEx`) which read pdata directly from target memory because they can't call the target's `RtlLookupFunctionEntry`.

For any real DLL, all four agree. It's in PEB, it's in the RB tree, `MemorySectionName` returns its full NT path, its pdata describes its real functions. A scanner that finds disagreement among them flags an anomaly.

Classic injection breaks one or more:

- **Private + executable shellcode**: nothing in (1), (2), or (3).
- **Reflective DLL injection**: not in (1) or (2). Threads execute in memory unattributed to any module.
- **Module stomping** (overwrite a victim DLL's `.text`): all four point at the victim, but the in-memory bytes no longer match the on-disk hash. ETW `Image_Load` events and integrity scanners catch it.
- **Phantom DLL Hollowing** (Forrest Orr): `SEC_IMAGE`-maps a transacted file. Clever, but the section name on disk no longer resolves post-rollback. Its own anomaly.

PhantomAlias loses only (3), and only in one form: `MemorySectionName` returns nothing because the region is private memory. (1), (2), and (4) stay fully consistent. The bet is that a single `MEM_PRIVATE` executable region is dramatically more common in real software than any of the other anomalies.

## The technique

Pick an alias DLL - any signed Microsoft DLL the process could reasonably depend on. Doesn't matter which; the technique is identical. Whatever you pick, that's the name the phantom wears.

The flow:

1. Allocate a private region for the payload.
2. If the alias DLL isn't already loaded, `LdrLoadDll` it. You need a real `LDR_DATA_TABLE_ENTRY` to mimic and a genuine module to sit next to.
3. Hand-build a phantom `LDR_DATA_TABLE_ENTRY` plus its own fresh `LDR_DDAG_NODE`. Clone every identity field off the real entry.
4. Take the loader lock. Splice the phantom into `PEB->Ldr` after the real entry. Insert it into `LdrpModuleBaseAddressIndex` keyed on the new region's base. Drop the lock.
5. Register unwind data for the payload code so `RtlVirtualUnwind` succeeds inside the region.
6. Dispatch the payload via a threadpool wait callback. No `CreateThread`.

After this, two entries with the same `BaseDllName` coexist in the loader. `EnumProcessModules` returns both. `RtlPcToFileHeader` returns whichever covers the queried IP - for any IP in the phantom region, that's the phantom, and the phantom says the alias name.

### 1. Allocate

```cpp
PVOID base = nullptr;
SIZE_T size = (payloadSize + unwindSize + 0x3000) & ~0xFFF;
NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size,
                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```

Plain version: ask the kernel for a chunk of process-private memory big enough to hold the payload, its unwind data, and some breathing room.

`NtAllocateVirtualMemory` is the native counterpart of `VirtualAllocEx`. The pseudo-handle `(HANDLE)-1` targets the current process. Passing `nullptr` for the base lets the kernel pick the address; if you'd rather not have it picked you can supply a hint. `MEM_COMMIT | MEM_RESERVE` does both steps in one call - reserves the address range and backs it with pages immediately. Initial protection is `PAGE_READWRITE` because we need to write the payload bytes; we promote to `PAGE_EXECUTE_READ` per-page once the bytes are in place. Strict W^X - never `PAGE_EXECUTE_READWRITE`, not even transiently, because the W→X transition is what EDR `NtProtectVirtualMemory` hooks alert on for shellcode loaders.

Memory regions on Windows are tagged by `Type` in `MEMORY_BASIC_INFORMATION`: `MEM_IMAGE` (backed by a SEC_IMAGE section, the type used for every loaded DLL), `MEM_MAPPED` (backed by a SEC_COMMIT section or pagefile), or `MEM_PRIVATE` (committed via `NtAllocateVirtualMemory` directly). Heaps and stacks are private; code rarely is. That asymmetry is what makes private+exec a meaningful signal.

### 2. Get a real loaded alias to mimic

```cpp
LdrEntry* target = FindLoadedModule(aliasName);
if (!target) {
    UnicodeString u;
    RtlInitUnicodeString(&u, aliasName);
    HANDLE h;
    LdrLoadDll(nullptr, nullptr, &u, &h);
    target = FindLoadedModule(aliasName);
}
```

We need a genuine `LDR_DATA_TABLE_ENTRY` for the alias DLL because we're going to clone almost every field off it. If the process already imports the DLL, the entry's already in PEB->Ldr - walk the list to find it. Otherwise call `LdrLoadDll` to load it normally; the loader will run `DllMain`, allocate an entry, splice it into PEB->Ldr, insert it into `LdrpModuleBaseAddressIndex`, all the standard machinery. From the kernel's perspective and from any EDR sensor's perspective, that's just another DLL load.

`LdrLoadDll` is the documented native equivalent of `LoadLibrary`. The `UnicodeString` parameter type (Microsoft calls it `UNICODE_STRING`) is three fields - `Length` and `MaximumLength` in bytes (not chars; this trips people up) plus a `Buffer` pointer - and is the universal NT string type for filenames, paths, and registry keys. `RtlInitUnicodeString` walks the wide buffer to find its NUL terminator and fills in the length.

The crucial fields we'll lift off the real entry are `TimeDateStamp` (from the PE's `IMAGE_FILE_HEADER`), `BaseNameHashValue` (a hash the loader computes from `BaseDllName` and uses for fast lookups), `OriginalBase` (the PE's preferred load address before ASLR), and `SigningLevel` (a single byte the loader sets from Code Integrity policy: 0 = unsigned, 4 = authenticode-signed, 12 = Microsoft-signed, etc.). Anything that's "supposed to be constant" for a given DLL is what an integrity check would compare.

### 3. Build the phantom

```cpp
auto* entry = (LdrEntry*) RtlAllocateHeap(heap, HEAP_ZERO_MEMORY,
                                          sizeof(LdrEntry) + 0x100);
auto* ddag  = (LdrDdagNode*) RtlAllocateHeap(heap, HEAP_ZERO_MEMORY,
                                             sizeof(LdrDdagNode));

entry->DllBase           = base;
entry->SizeOfImage       = (ULONG)size;
entry->EntryPoint        = (BYTE*)base + entryRva;
entry->Flags             = LDRP_IMAGE_DLL
                         | LDRP_ENTRY_PROCESSED
                         | LDRP_PROCESS_ATTACH_CALLED    // skip DllMain
                         | LDRP_DONT_CALL_FOR_THREADS;   // skip thread callbacks
entry->TimeDateStamp     = target->TimeDateStamp;
entry->BaseNameHashValue = target->BaseNameHashValue;
entry->OriginalBase      = target->OriginalBase;
entry->SigningLevel      = target->SigningLevel;

CloneUnicodeString(&entry->BaseDllName, &target->BaseDllName);
CloneUnicodeString(&entry->FullDllName, &target->FullDllName);

ddag->State              = LdrModulesReadyToRun;
ddag->LoadCount          = 1;
ddag->Modules.Flink      = &entry->NodeModuleLink;
ddag->Modules.Blink      = &entry->NodeModuleLink;
ddag->CondenseLink.Flink = &ddag->CondenseLink;
ddag->CondenseLink.Blink = &ddag->CondenseLink;

entry->DdagNode             = ddag;
entry->NodeModuleLink.Flink = &ddag->Modules;
entry->NodeModuleLink.Blink = &ddag->Modules;
entry->HashLinks.Flink      = &entry->HashLinks;
entry->HashLinks.Blink      = &entry->HashLinks;
```

Allocate the two structs on the process heap via `RtlAllocateHeap` (the documented heap-allocator backing `malloc`/`HeapAlloc`); we're putting them somewhere the loader can deref forever without them moving. The over-allocation of `0x100` bytes past `sizeof(LdrEntry)` gives us slack for the tail fields the loader keeps adding in Windows updates - `LoadReason`, `ImplicitPathOptions`, `ReferenceCount`, etc.

`LDR_DATA_TABLE_ENTRY` itself: the loader's per-module record. The first three fields are the doubly-linked list nodes that splice into PEB->Ldr's three lists. Then `DllBase`, `EntryPoint`, `SizeOfImage`, the two `UNICODE_STRING`s for the file name. Then a `Flags` bitfield. Then the more interesting tail: `DdagNode` (pointer to the dependency-graph node, added in Win8.1), `BaseAddressIndexNode` (the embedded `RTL_BALANCED_NODE` for the RB tree), `MappingInfoIndexNode`, `LoadTime`, `LoadReason` (an enum: `LoadReasonStaticDependency`, `LoadReasonDelayloadDependency`, etc.). We zero everything, then fill what matters.

The `Flags` we set:
- `LDRP_IMAGE_DLL` (`0x4`) - this entry represents a DLL, not the EXE.
- `LDRP_ENTRY_PROCESSED` (`0x4000`) - the loader has fully initialized this entry.
- `LDRP_PROCESS_ATTACH_CALLED` (`0x80000`) - `DllMain(DLL_PROCESS_ATTACH)` has already run. Load-bearing: without it, anything that walks the init-order list to dispatch DllMain hands control to whatever's at `entry->EntryPoint`.
- `LDRP_DONT_CALL_FOR_THREADS` (`0x40000`) - skip this entry when dispatching `DLL_THREAD_ATTACH` / `DLL_THREAD_DETACH` on thread create/exit. Same reason.

`LDR_DDAG_NODE` is the loader's "this is the dependency-graph node for module X" record. It tracks the module's lifecycle state (`LdrModulesReadyToRun` is the steady state), its load count (number of outstanding `LdrLoadDll` references), its dependencies and incoming dependencies (`LDRP_CSLIST` chains), and a `Modules` list that holds back-pointers to every `LDR_DATA_TABLE_ENTRY` belonging to this DDAG node - usually one, occasionally more in delay-load scenarios.

The DdagNode is **not shared** with the real target. Sharing it means an unload of the real module decrements the shared node's `LoadCount`, which can yank the phantom's reference count down with it and free your code mid-execution. Always allocate your own DdagNode and self-reference its `CondenseLink` (`Flink = Blink = &CondenseLink`) - the loader walks this list during cycle detection in its dependency graph; an uninitialized field crashes the walker.

The `HashLinks` field is part of `LdrpHashTable`, a 32-bucket hash table keyed on `BaseNameHashValue & 0x1F` that the loader uses for name-based lookups. We self-reference it (it's a `LIST_ENTRY`, so `Flink = Blink = &HashLinks`) rather than actually splicing into the hash bucket. Hash-bucket collisions are normal - the loader walks the chain - so an unspliced entry just isn't reachable by name lookup, which is fine because we want IP-based lookups to find us, not name-based ones.

### 4. Splice and insert

```cpp
LdrLockLoaderLock(0, &state, &cookie);
InsertAfter(&target->InLoadOrderLinks,   &entry->InLoadOrderLinks);
InsertAfter(&target->InMemoryOrderLinks, &entry->InMemoryOrderLinks);
entry->InInitializationOrderLinks.Flink = &entry->InInitializationOrderLinks;
entry->InInitializationOrderLinks.Blink = &entry->InInitializationOrderLinks;
RtlRbInsertNodeEx(tree, parent, goesRight, &entry->BaseAddressIndexNode);
LdrUnlockLoaderLock(0, cookie);
```

Two mutations: splice into the PEB lists, then insert into the RB tree. Both protected by the same lock.

`LdrLockLoaderLock` / `LdrUnlockLoaderLock` are documented exports that take the loader's primary lock - the same one Windows takes for every `LdrLoadDll`, `LdrUnloadDll`, list mutation, and DllMain dispatch. It's an exclusive lock (a `RTL_CRITICAL_SECTION` on older builds, a SRW lock since Win10). Without holding it, a concurrent loader operation from another thread can see half-spliced state and corrupt the list.

The PEB lists are `LIST_ENTRY` chains - the standard Windows doubly-linked list primitive, where each element has a `Flink` (forward link) and a `Blink` (backward link). Inserting after a given node `n` with a new node `e` is four pointer writes: `e->Flink = n->Flink`, `e->Blink = n`, `n->Flink->Blink = e`, `n->Flink = e`. We do this for `InLoadOrderLinks` (the canonical order: load order across the process lifetime) and `InMemoryOrderLinks` (order by memory address). The third list, `InInitializationOrderLinks`, holds entries whose DllMain hasn't yet been called; since we've flagged ourselves as already-initialized, we stay out of it - self-reference it so nothing traversing it walks off a NULL.

`LdrpModuleBaseAddressIndex` is a red-black tree whose nodes are `RTL_BALANCED_NODE` structures embedded inside each `LDR_DATA_TABLE_ENTRY`. RB trees keep insert/lookup/delete at O(log n) by enforcing a coloring invariant on top of binary search. The `RTL_BALANCED_NODE` packs the red/black bit into the low bits of the parent pointer (`ParentValue & ~3` gives the real parent address) - a standard trick that saves a byte but costs you a mask on every traversal.

The tree address isn't exported. To find it, walk up from any known entry's `BaseAddressIndexNode` to the root via `ParentValue & ~3` until you hit `NULL`. That gives you the root node pointer. Then scan ntdll's writable data sections for a `PVOID` slot whose value equals the root. Since `RTL_RB_TREE` is `{ Root, Min }` - two pointers - and `Root` is at offset 0, the matching slot's address *is* the tree's address. Validate by checking that `slot[1]` (which would be the `Min` field) is itself a node that walks back to the same root.

`RtlRbInsertNodeEx` is exported by ntdll since Windows 8. Signature: `(tree, parent, goesRight, newNode)`. The caller is responsible for the BST descent (walk down from root comparing `DllBase`, find the leaf where the new key belongs, remember whether it goes left or right of that leaf). The function then links the new node, updates the tree's `Min` if the new node is the leftmost, and runs the RB fixup (rotations + recoloring) to restore the invariant.

Once inserted, any call to `RtlPcToFileHeader` with an IP in `[base, base+size)` traverses the tree, finds our node, and returns the `LDR_DATA_TABLE_ENTRY` it's embedded in - which says the alias name.

<img width="493" height="358" alt="image" src="https://github.com/user-attachments/assets/b8f4ccb2-2e32-49b0-8166-458810307e41" />

### 5. Register unwind data

```cpp
PVOID handle = nullptr;
RtlAddGrowableFunctionTable(&handle, runtimeFunctions, count, count,
                            (ULONG_PTR)base, (ULONG_PTR)base + size);
```

Stack walkers need to know, for each instruction pointer, what `RUNTIME_FUNCTION` describes the prologue of the function containing it, and what `UNWIND_INFO` describes the operations the unwinder needs to reverse to get back to the caller. Without that data, x64 stack walking fails immediately: the unwinder has no way to determine how many bytes to pop, what registers to restore, or whether there's a saved frame pointer.

For statically loaded PE modules, the loader reads `IMAGE_DIRECTORY_ENTRY_EXCEPTION` from the PE header and registers the module's `.pdata` automatically. For dynamic code - JIT engines, manually mapped DLLs, our payload region - you have to register it yourself.

`RtlAddGrowableFunctionTable` is one of two options for this (the other being the older `RtlAddFunctionTable`). It populates an in-process structure called `LdrpInvertedFunctionTable` so that `RtlLookupFunctionEntry` finds your entries when walked. The `Growable` variant supports later updates to the registered array; we don't need that, but `RtlAddFunctionTable`'s API is rougher and the growable form is the modern choice.

The `runtimeFunctions` array is a sorted (ascending by `BeginAddress`) sequence of `RUNTIME_FUNCTION` records: `{ BeginAddress, EndAddress, UnwindData }`, all RVAs from the `base` argument. `UnwindData` points to an `UNWIND_INFO` structure that describes the prologue as a sequence of `UNWIND_CODE`s - `UWOP_PUSH_NONVOL`, `UWOP_ALLOC_SMALL`, `UWOP_ALLOC_LARGE`, `UWOP_SET_FPREG`, etc. - each tagged with the byte offset in the prologue where it took effect. The unwinder reverses these in order to restore the calling frame.

For a DLL payload, use the agent's own `.pdata` directly from its mapped image - extract `IMAGE_DIRECTORY_ENTRY_EXCEPTION` and pass that pointer. For raw position-independent code, you need to ship the `RUNTIME_FUNCTION[]` and `UNWIND_INFO` blobs separately and adjust their RVAs at load time. There's no clever way around it - the unwinder needs the metadata. Without it, walks die at the first frame inside your code.

### 6. Dispatch via threadpool

```cpp
HANDLE trigger;
NtCreateEvent(&trigger, EVENT_ALL_ACCESS, nullptr, SynchronizationEvent, FALSE);
PTP_WAIT wait;
TpAllocWait(&wait, (PTP_WAIT_CALLBACK)payloadAddress, nullptr, nullptr);
TpSetWait(wait, trigger, nullptr);
NtSetEvent(trigger, nullptr);
```

No `CreateThread`. The threadpool worker that ends up running the payload was already there - every Windows process gets a default thread pool (`TppWorkerFactory`) at startup, sized by `SetThreadpoolThreadMinimum`/`Maximum`. Its workers spend their lives in `ntdll!TppWorkerThread` waiting for work.

`TpAllocWait` (and its Win32 wrapper `CreateThreadpoolWait`) registers a callback that fires when a kernel event becomes signaled. The thread pool's internals call your callback via `TppExecuteWaitCallback`, on whichever worker is free. `TpSetWait` associates the wait with a specific `HEVENT`; `NtSetEvent` signals it; the worker picks up the work item and invokes the callback.

The result, from a detection standpoint: the first frame of payload execution sits inside `ntdll!TppExecuteWaitCallback`. The enclosing thread's `TEB.StartAddress` (the address logged by every EDR's `PspCreateThread` hook) is `ntdll!TppWorkerThread` - identical to every other worker in every other Windows process. No suspicious thread create. No private-memory start address. The thread doesn't know it just ran something unusual; it just sees a callback.

A stack trace of a thread running the payload:

```
ntdll!NtWaitForSingleObject
KernelBase!WaitForSingleObjectEx
<alias>!<offset>                ← the payload
ntdll!TppExecuteWaitCallback
ntdll!TppWorkerThread
ntdll!RtlUserThreadStart
```

The payload's frames symbolize as the alias DLL because that's what the AVL hands back. The walker continues past them cleanly back to `ntdll!RtlUserThreadStart`, the universal start of every Windows user-mode thread.

## Why this evades the usual catches

**Thread start address scanning.** Every serious EDR logs thread creation and inspects the start address. A thread starting in private memory is one of the highest-confidence shellcode indicators there is. We never create a thread. The worker has been there since process startup, with `TEB.StartAddress` in ntdll.

**Module integrity checks.** The real alias DLL is byte-identical to disk. Heuristics that compare loaded-module bytes against a clean image - Defender's image-hash logic, custom YARA over `MEM_IMAGE` ranges, ProcessMonitor signatures - have nothing to flag on it. Our region isn't `MEM_IMAGE`, so it isn't compared against any DLL.

**Module enumeration.** We're in `PEB->Ldr` with a valid `BaseDllName`, `FullDllName`, `DllBase`, and `SizeOfImage`. A snapshot-and-diff tool sees a second entry with the same name appear over time, but that's only an anomaly to tools specifically looking for duplicate-name LDR entries. Most aren't.

**Cross-process stack walks.** `RtlPcToFileHeader` returns the phantom for any IP in the region. `RtlAddGrowableFunctionTable` makes `RtlLookupFunctionEntry` succeed. dbghelp's `StackWalkEx` symbolizes payload frames as `<alias>!<offset>` and unwinds cleanly back to ntdll.

**ETW image-load events.** None. `Microsoft-Windows-Kernel-Process/Image_Load` fires from `MiCreateImageFileMap` in the kernel. We never enter that path because we never create an image section.

## Validation against Moneta

I ran [Moneta](https://github.com/forrest-orr/moneta) Forrest Orr's open-source scanner against a reference implementation. The relevant output, with addresses redacted:

<img width="1719" height="867" alt="image" src="https://github.com/user-attachments/assets/755cb1e5-9a40-4cb7-9883-864bdd46ceb8" />

(Representative; exact addresses vary per run.)

One finding. **Abnormal private executable memory** on the code page. That's real and we didn't hide it. The region is `PAGE_EXECUTE_READ`, `MEM_PRIVATE`, and a thread is executing inside it. Moneta reports exactly what's there.

What Moneta did *not* flag:
- No "modified code in image" - no image was touched.
- No "non-module thread start address" - the thread's start is `ntdll!TppWorkerThread`.
- No "PE header modified" - no PE header was modified.
- No "missing PEB module" - the phantom is in PEB and Moneta accepts it.
- No `MemorySectionName` mismatch - Moneta only checks this against `MEM_IMAGE` regions.

For comparison, the classic injection methods tested in Forrest Orr's own Moneta posts each light up four to seven findings, including the high-confidence ones ("modified code in image," "missing PEB module"). One finding versus seven is not a tie.

## Is `MEM_PRIVATE + executable` a useful IOC on its own?

No, and the whole technique rests on this claim.

Run Moneta against a vanilla Windows 11 workstation with Citrix Workspace installed. Citrix's `wfshell.exe`, `concentr.exe`, and `ssonsvr.exe` all allocate `MEM_PRIVATE` executable regions for their in-process hooks and IPC marshalling. Every one of them gets the same "abnormal private executable memory" message. So does Adobe Reader's protected-mode broker. So does the .NET CLR's JIT-emitted code in any managed application. So does V8's stub code in Chrome's renderer.

A scanner that fires on every private-exec region produces hundreds of false positives per minute on a busy enterprise workstation. EDR vendors know this. What production EDRs actually do is correlate: private-exec region *plus* a thread starting from it, *plus* RWX history, *plus* an unsigned module loading nearby, *plus* network egress, *plus* a suspicious parent process. Any single signal is noise. The combination is the alert.

PhantomAlias produces the signal. It produces none of the correlating ones. The thread didn't start from the region. The memory was never RWX. No unsigned module loaded. The parent process is whatever you injected into.

Scanners that hard-flag every private-exec region without correlation do catch this. There are some. They produce enough false positives that customers turn those rules off.

## Where it breaks

- **Kernel-mode visibility.** A driver-based scanner that walks `SECTION_OBJECT_POINTERS` sees our region has no associated `FileObject`. Trivial to flag. The technique is user-mode; this is out of scope.
- **EDRs with deep `NtAllocateVirtualMemory` telemetry.** A few hook the syscall and log every `PAGE_EXECUTE_*` allocation with stack context. The allocation will be logged. Whether it escalates depends on whatever else the process is doing.
- **Stripped PIC payloads.** Stack walks through the payload's own frames require `RUNTIME_FUNCTION[]` and `UNWIND_INFO` for the shellcode. If you ship raw stripped shellcode with no unwind metadata, walks die at the first payload frame. There's no clever way around it - the unwinder needs the metadata.
- **Memory dumps + offline analysis.** Volatility, MemProcFS, anything that diffs in-memory against on-disk: the private region is visible and contains code. Online evasion isn't offline immunity.
- **Per-region image integrity check.** A scanner that takes every PEB->Ldr entry, queries `MemorySectionName` on its `DllBase`, and rejects entries whose region isn't `MEM_IMAGE` catches the technique cleanly. The fix is to back the region with a real `SEC_IMAGE` mapping of a sacrificial signed DLL - trades the "one private region" tell for a duplicate `MEM_IMAGE` mapping of the same signed file. Pick your tell.

## Closing

The interesting move isn't any single primitive. Reflective loading gave us manual PE mapping. Module stomping showed it was fine to put your code inside someone else's address space. `RtlAddGrowableFunctionTable` has been in red-team toolkits since at least 2017. RB tree manipulation surfaces in private toolkits and System Informer's source.

What changes the detection math is keeping the original module clean. Module stomping always traded "real LDR entry" for "modified image." PhantomAlias keeps both: the genuine, unmodified alias module in memory, plus a phantom that wears its identity. The forensic story shifts from "this module's `.text` doesn't match disk" to "there are two entries with the same name in the loader and one is private memory." The first is malicious-by-default. The second is weird.

The failure mode is bounded and honest: one private executable region. If defenders flag every `MEM_PRIVATE + PAGE_EXECUTE_READ` region regardless of context, they catch you. If their detection budget accepts that the signal needs corroboration to be useful - which production EDRs do, because the false-positive rate forces them to - they don't.
