module Lang.AlphaEq where

import Common.Location
import Data.Int

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
  | LetV [(Location, Value)] Value
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
  | LetP [(Location, Value)] Pred
  deriving (Show, Eq)

-- Tail
data Tail
  = Halt Pred
  | -- LetLoop Bindings Pred Base Recur
    LetLoop [(Location, Value)] Pred Tail [Value]
  | IfT Pred Tail Tail
  | LetT [(Location, Value)] Tail
  deriving (Show, Eq)

factorial :: Program
factorial =
  Module $
    LetLoop
      [(Location Uniquify 0, VNum 5), (Location Uniquify 1, VNum 1)]
      (Eq (VLoc (Location Uniquify 0)) (VNum 0))
      (Halt $ Gt (VLoc (Location Uniquify 1)) (VNum 1000))
      [Sub (VLoc (Location Uniquify 0)) $ VNum 1, Mul (VLoc (Location Uniquify 0)) (VLoc (Location Uniquify 1))]
