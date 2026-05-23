module Lang.Predless where

import Data.Int

-- Program
data Program = Module [Statement]
  deriving (Show, Eq)

-- Labels
-- Lookup Tables and Code
data Label = RealBase | FakeBase | Code Int64 | Success | Failure
  deriving (Show, Eq)

-- Location
-- Registers and "Frame Variables"
data Location = Reg Register | Rel Register Offset
  deriving (Show, Eq)

data Register = CL | RCX | RAX | RBX | RDX | R8 | R9 | R10 | CompareResultRegister | BasePointerRegister | InputBaseRegister
  deriving (Show, Eq)

type Offset = Int64

-- Triv
data Triv
  = TrivLoc Location
  | TrivNum Int64
  deriving (Show, Eq)

-- Statement
data Statement
  = Set Location Triv
  | SetAdd Location Triv
  | SetSub Location Triv
  | SetMul Location Triv
  | SetBitNot Location
  | SetBitAnd Location Triv
  | SetBitXor Location Triv
  | SetBitIor Location Triv
  | SetShiftL Location Triv
  | SetShiftR Location Triv
  | LoadAddr Register Label
  | PopCount Register Location
  | BitScanReverse Register Location
  | TrailZeroCount Register Location
  deriving (Show, Eq)
