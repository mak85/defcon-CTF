module Interpreter.Source where

import Lang.Source

data Val
  = Val

data Obs = Either String Val
  deriving Show

interp :: Program -> Obs
interp Module defs tail = interpTail ()
