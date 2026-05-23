module Lang.Jumpy where

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
  | SetBitAnd Location Triv
  | SetBitXor Location Triv
  | SetBitIor Location Triv
  | SetShiftL Location Triv
  | SetShiftR Location Triv
  | Jump Label
  | CmpJump Pred Label
  | WithLabel Label Statement
  deriving (Show, Eq)
