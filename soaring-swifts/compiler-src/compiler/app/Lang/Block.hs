module Lang.Block where

import Data.Int
import Common.Location (Location, Label)

-- Program
data Program = Module [Block] Tail
  deriving (Show, Eq)

-- Triv
data Triv
  = TrivLoc Location
  | TrivNum Int64
  deriving (Show, Eq)

-- Predicates
data Pred
  = Lt Triv Triv
  | Eq Triv Triv
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
  deriving (Show, Eq)

-- Block
data Block = Block Label Tail
  deriving (Show, Eq)

-- Tail
data Tail
  = Jump Label
  | IfT Pred Label Label
  | BeginT [Effect] Tail
  deriving (Show, Eq)
