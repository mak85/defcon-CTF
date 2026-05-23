module Lang.Seq where

import Data.Int
import Common.Location

-- Program
data Program = Module Tail
  deriving (Show, Eq)

-- Values
data Value
  = VLoc Location
  | VNum Int64
  | Add Value Value
  | Sub Value Value
  | Mul Value Value
  | BitAnd Value Value
  | BitXor Value Value
  | BitIor Value Value
  | ShiftL Value Value
  | ShiftR Value Value
  | IfV Pred Value Value
  | BeginV [Effect] Value
  deriving (Show, Eq)

-- Predicates
data Pred
  = Not Pred
  | Lt Value Value
  | Gt Value Value
  | Eq Value Value
  | Leq Value Value
  | Geq Value Value
  | IfP Pred Pred Pred
  | BeginP [Effect] Pred
  deriving (Show, Eq)

-- Effect
data Effect
  = Set Location Value
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
