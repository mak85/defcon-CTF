module Pass.EmbedRuntime where

import Common.Constants (failureLabelHex, fakeBaseHex, realBaseHex, successLabelHex)

-- Embeds the runtime system around the generated code
-- This includes:
-- - Setting up RealBase and FakeBase memory regions
-- - Initializing BasePointerRegister
-- - The main execution loop
-- - Success/Failure handlers

embedRuntime :: [String] -> [String]
embedRuntime body = prologue ++ mainLoopStart ++ body ++ mainLoopEnd ++ epilogue

-- mmap syscall (Linux x86-64) at fixed address
-- rdi = addr, rsi = length, rdx = prot, r10 = flags, r8 = fd, r9 = offset
-- syscall number 9
mmapFixedSyscall :: String -> [String]
mmapFixedSyscall addrHex =
  [ "mov rdi, " ++ addrHex, -- addr (fixed address)
    "mov rsi, 0x1000", -- length (4KB page)
    "mov rdx, 0x3", -- prot: PROT_READ | PROT_WRITE
    "mov r10, 0x32", -- flags: MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED
    "mov r8, -1", -- fd: -1 for anonymous
    "mov r9, 0", -- offset: 0
    "mov rax, 9", -- syscall number for mmap
    "syscall"
  ]

-- mmap syscall (Linux x86-64) at any address (kernel chooses)
-- Returns address in rax
mmapAnySyscall :: [String]
mmapAnySyscall =
  [ "mov rdi, 0", -- addr: NULL (let kernel choose)
    "mov rsi, 0x1000", -- length (4KB page)
    "mov rdx, 0x3", -- prot: PROT_READ | PROT_WRITE
    "mov r10, 0x22", -- flags: MAP_PRIVATE | MAP_ANONYMOUS
    "mov r8, -1", -- fd: -1 for anonymous
    "mov r9, 0", -- offset: 0
    "mov rax, 9", -- syscall number for mmap
    "syscall"
  ]

-- read syscall (Linux x86-64)
-- rdi = fd, rsi = buf, rdx = count
-- syscall number 0
readSyscall :: String -> String -> [String]
readSyscall bufReg countHex =
  [ "mov rdi, 0", -- fd: stdin
    "mov rsi, " ++ bufReg, -- buf
    "mov rdx, " ++ countHex, -- count
    "mov rax, 0", -- syscall number for read
    "syscall"
  ]

header :: [String]
header =
  [ "section .text",
    "global start",
    "start:"
  ]

prologue :: [String]
prologue =
  concat
    [ header,
      -- mmap input buffer (dynamically allocated)
      mmapAnySyscall,
      -- store input buffer address in r13 (InputBaseRegister)
      ["mov r13, rax"],
      -- read up to a page from stdin into input buffer
      readSyscall "r13" "0x1000",
      -- mmap real memory region
      mmapFixedSyscall realBaseHex,
      -- mmap fake memory region
      mmapFixedSyscall fakeBaseHex,
      -- initialize base pointer to real region
      ["mov rbp, " ++ realBaseHex]
    ]

mainLoopStart :: [String]
mainLoopStart =
  ["main_loop:"]

mainLoopEnd :: [String]
mainLoopEnd =
  [ "mov rax, " ++ realBaseHex,
    "mov rax, QWORD [rax]",
    "cmp rax, " ++ successLabelHex,
    "je success_handler",
    "cmp rax, " ++ failureLabelHex,
    "je failure_handler",
    "jmp main_loop"
  ]

epilogue :: [String]
epilogue = successHandler ++ failureHandler

-- Handler for successful termination
successHandler :: [String]
successHandler =
  [ "success_handler:",
    "mov rdi, 0", -- exit code 0
    "mov rax, 60", -- syscall number for exit
    "syscall"
  ]

-- Handler for failed termination
failureHandler :: [String]
failureHandler =
  [ "failure_handler:",
    "mov rdi, 1", -- exit code 1
    "mov rax, 60", -- syscall number for exit
    "syscall"
  ]
