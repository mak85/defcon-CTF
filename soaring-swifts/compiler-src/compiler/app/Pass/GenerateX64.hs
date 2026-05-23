module Pass.GenerateX64 where

import Common.Constants (failureLabelHex, fakeBaseHex, realBaseHex, successLabelHex)
import qualified Lang.Predless as S

generateX64 :: S.Program -> [String]
generateX64 (S.Module stmts) = concatMap generateStatement stmts

generateStatement :: S.Statement -> [String]
generateStatement (S.Set loc triv) =
  [ "mov r11, " ++ generateTriv triv,
    "mov " ++ generateLocation loc ++ ", r11"
  ]
generateStatement (S.SetAdd loc triv) =
  patch "add" loc triv
generateStatement (S.SetSub loc triv) =
  patch "sub" loc triv
generateStatement (S.SetMul loc triv) =
  patch "imul" loc triv
generateStatement (S.SetBitNot loc) =
  ["not " ++ generateLocation loc]
generateStatement (S.SetBitAnd loc triv) =
  patch "and" loc triv
generateStatement (S.SetBitXor loc triv) =
  patch "xor" loc triv
generateStatement (S.SetBitIor loc triv) =
  patch "or" loc triv
generateStatement (S.SetShiftL loc triv) =
  patch "shl" loc triv
generateStatement (S.SetShiftR loc triv) =
  patch "shr" loc triv
generateStatement (S.LoadAddr reg label) =
  ["mov " ++ generateRegister reg ++ ", " ++ generateLabel label]
generateStatement (S.PopCount reg loc) =
  ["popcnt " ++ generateRegister reg ++ ", " ++ generateLocation loc]
generateStatement (S.BitScanReverse reg loc) =
  ["bsr " ++ generateRegister reg ++ ", " ++ generateLocation loc]
generateStatement (S.TrailZeroCount reg loc) =
  ["tzcnt " ++ generateRegister reg ++ ", " ++ generateLocation loc]

-- Check if location is memory (not a register)
isMem :: S.Location -> Bool
isMem (S.Rel _ _) = True
isMem (S.Reg _) = False

-- Check if triv is a memory location
isTrivMem :: S.Triv -> Bool
isTrivMem (S.TrivLoc loc) = isMem loc
isTrivMem (S.TrivNum _) = False

-- Patch memory-memory operations using r11 as scratch
patch :: String -> S.Location -> S.Triv -> [String]
patch op loc triv
  | triv /= (S.TrivLoc (S.Reg S.CL)) && (op == "shr" || op == "shl") =
      [ "mov r11, " ++ generateLocation loc,
        "mov rcx, " ++ generateTriv triv,
        op ++ " r11, cl",
        "mov " ++ generateLocation loc ++ ", r11"
      ]
  | (S.TrivNum n) <- triv =
      [ "mov r11, " ++ generateLocation loc,
        "mov r14, " ++ generateTriv (S.TrivNum n),
        op ++ " r11, r14",
        "mov " ++ generateLocation loc ++ ", r11"
      ]
  | otherwise =
      [ "mov r11, " ++ generateLocation loc,
        op ++ " r11, " ++ generateTriv triv,
        "mov " ++ generateLocation loc ++ ", r11"
      ]

generateLocation :: S.Location -> String
generateLocation (S.Reg reg) = generateRegister reg
generateLocation (S.Rel reg offset)
  | offset > 0 = "QWORD [" ++ generateRegister reg ++ " + " ++ show offset ++ "]"
  | otherwise = "QWORD [" ++ generateRegister reg ++ " - " ++ show (abs offset) ++ "]"

generateRegister :: S.Register -> String
generateRegister S.CL = "cl"
generateRegister S.RAX = "rax"
generateRegister S.RBX = "rbx"
generateRegister S.RCX = "rcx"
generateRegister S.RDX = "rdx"
generateRegister S.R8 = "r8"
generateRegister S.R9 = "r9"
generateRegister S.R10 = "r10"
generateRegister S.CompareResultRegister = "r12"
generateRegister S.BasePointerRegister = "rbp"
generateRegister S.InputBaseRegister = "r13"

generateTriv :: S.Triv -> String
generateTriv (S.TrivLoc loc) = generateLocation loc
generateTriv (S.TrivNum n) = show n

generateLabel :: S.Label -> String
generateLabel S.RealBase = realBaseHex
generateLabel S.FakeBase = fakeBaseHex
generateLabel (S.Code n) = show n
generateLabel S.Success = successLabelHex
generateLabel S.Failure = failureLabelHex
