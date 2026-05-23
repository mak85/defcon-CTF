module Private.FlagChecker where

import Data.Bits (shiftL, shiftR, xor, (.&.), (.|.))
import Data.Char (ord)
import Data.Int
import Data.List (unfoldr, foldl')
import Lang.Source
import Data.Word (Word64)

type Keys = [Int64]

packWord :: String -> Int64
packWord s = foldr (\(i, c) acc -> acc .|. (fromIntegral (ord c) `shiftL` (i * 8))) 0 (zip [0..] (take 8 (s ++ repeat '\0')))

-- Complex checker: rolling hash over multiple iterations
makeFlagChecker :: Keys -> String -> Program String
makeFlagChecker keys flag =
  let nWords = (length flag + 7) `div` 8
      flagWords = [packWord (drop (i*8) flag) | i <- [0..nWords-1]]
      keysExt = take 32 (keys ++ repeat 0xDEADBEEF)
      -- Each iteration: hash = (hash * k0) XOR input[i] + k1
      computeHash iters ws =
        foldl' (\h (i, w) -> ((h * (keysExt !! 0)) `xor` w) + (keysExt !! 1))
               0
               (take iters (cycle (zip [0..] ws)))
      iters = nWords * 3
      expectedHash = computeHash iters flagWords
      -- Build the hash expression
      step h (i, _) =
        Add (BitXor (Mul h (VNum (keysExt !! 0)))
                    (InputWord (fromIntegral (i `mod` nWords))))
            (VNum (keysExt !! 1))
      hashExpr = foldl' step (VNum 0) (take iters (cycle (zip [0..] flagWords)))
      -- Also strict per-word check
      mkCheck i =
        let k = keysExt !! (i + 8)
            fw = flagWords !! i
        in Eq (BitXor (InputWord (fromIntegral i)) (VNum k)) (VNum (fw `xor` k))
      wordChecks = map mkCheck [0..nWords-1]
      hashCheck = Eq hashExpr (VNum expectedHash)
      allChecks = hashCheck : wordChecks
      combined = foldr1 (\a b -> IfP a b (Eq (VNum 0) (VNum 1))) allChecks
  in Module (Halt combined)
