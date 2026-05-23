module Lang.FlatBlock where

import Data.Int
import Common.Location (Location, Label)

-- Program: entry has its own effects
data Program = Module [Block] [Effect] Tail
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
  deriving (Show, Eq)

-- Block: flattened to have effects inline
data Block = Block Label [Effect] Tail
  deriving (Show, Eq)

-- Tail
data Tail
  = Jump Label
  | IfT Pred Label Label
  deriving (Show, Eq)
