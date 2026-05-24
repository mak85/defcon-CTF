module Private.FlagChecker where

import Data.Bits (shiftL, xor, (.|.))
import Data.Char (ord)
import Data.Int
import Data.List (foldl')
import Lang.Source

type Keys = [Int64]

packWord :: String -> Int64
packWord s = foldr (\(i, c) acc -> acc .|. (fromIntegral (ord c) `shiftL` (i * 8))) 0 (zip [0..] (take 8 (s ++ repeat '\0')))

makeFlagChecker :: Keys -> String -> Program String
makeFlagChecker keys flag =
  let nWords = (length flag + 7) `div` 8
      flagWords = [packWord (drop (i*8) flag) | i <- [0..nWords-1]]
      keysExt = take 256 (keys ++ repeat 0xDEADBEEF)
      -- Per-word: simple per-word equality
      mkCheck i =
        let k = keysExt !! i
            fw = flagWords !! i
        in Eq (BitXor (InputWord (fromIntegral i)) (VNum k)) (VNum (fw `xor` k))
      checks = map mkCheck [0..nWords-1]
      eqAnd = foldr1 (\a b -> IfP a b (Eq (VNum 0) (VNum 1))) checks
      -- Wrap in a LetLoop that iterates many times before checking
      finalP =
        LetLoop
          [("counter", VNum 100)]
          (Eq (Identifier "counter") (VNum 0))
          (Halt eqAnd)
          [Sub (Identifier "counter") (VNum 1)]
  in Module finalP
