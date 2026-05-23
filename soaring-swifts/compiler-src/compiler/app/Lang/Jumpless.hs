module Lang.Jumpless where

import Data.Int
import Common.Location (Location, Label)

-- Program
data Program = Module [Statement]
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
  | Enable Label
  | Disable Label
  | CmpDisable Pred Label
  deriving (Show, Eq)
