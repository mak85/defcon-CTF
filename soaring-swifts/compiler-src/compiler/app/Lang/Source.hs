module Lang.Source where
import Data.Int

-- Program
data Program a = Module (Tail a)
  deriving (Show)

-- Values
data Value a
  = Identifier a
  | VNum Int64
  | InputWord Int64
  | Add (Value a) (Value a)
  | Sub (Value a) (Value a)
  | Mul (Value a) (Value a)
  | BitAnd (Value a) (Value a)
  | BitXor (Value a) (Value a)
  | BitIor (Value a) (Value a)
  | ShiftL (Value a) (Value a)
  | ShiftR (Value a) (Value a)
  | IfV (Pred a) (Value a) (Value a)
  | LetV [(a, (Value a))] (Value a)
  deriving (Show)

-- Predicates
data Pred a
  = Not (Pred a)
  | Lt (Value a) (Value a)
  | Gt (Value a) (Value a)
  | Eq (Value a) (Value a)
  | Leq (Value a) (Value a)
  | Geq (Value a) (Value a)
  | IfP (Pred a) (Pred a) (Pred a)
  | LetP [(a, (Value a))] (Pred a)
  deriving (Show)

-- Tail
data Tail a
  = Halt (Pred a)
  | -- LetLoop Bindings Pred Base Recur
    LetLoop [(a, (Value a))] (Pred a) (Tail a) [Value a]
  | IfT (Pred a) (Tail a) (Tail a)
  | LetT [(a, (Value a))] (Tail a)
  deriving (Show)
