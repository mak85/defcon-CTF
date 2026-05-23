module Lang.Norm where

import Data.Int
import Common.Location (Location)

-- Program
data Program = Module Tail
  deriving (Show, Eq)

-- Triv
data Triv
  = TrivLoc Location
  | TrivNum Int64
  deriving (Show, Eq)

-- Predicates
data Pred
  = Not Pred
  | Lt Triv Triv
  | Gt Triv Triv
  | Eq Triv Triv
  | Leq Triv Triv
  | Geq Triv Triv
  | IfP Pred Pred Pred
  | BeginP [Effect] Pred
  deriving (Show, Eq)

-- Effect
data Effect
  = Set Location Triv
  | SetAdd Location Triv
  | SetSub Location Triv
  | SetMul Location Triv
  | SetBitAnd Location Triv
  | SetBitXor Location Triv
  | SetBitIor Location Triv
  | SetShiftL Location Triv
  | SetShiftR Location Triv
  | BeginE [Effect] Effect
  | IfE Pred Effect Effect
  deriving (Show, Eq)

-- Tail
data Tail
  = Halt Pred
  | IfT Pred Tail Tail
  | BeginT [Effect] Tail
  | Loop Pred Tail [Effect]
  deriving (Show, Eq)
