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
      keysExt = take 128 (keys ++ repeat 0xDEADBEEF)
      -- 8 rounds per word
      rndS a k1 k2 k3 = BitXor (Mul (Add a (VNum k1)) (VNum k2)) (VNum k3)
      rndC a k1 k2 k3 = ((a + k1) * k2) `xor` k3
      mixSym a i = foldl' (\acc r -> rndS acc (keysExt!!((i*24+r*3) `mod` 128)) (keysExt!!((i*24+r*3+1) `mod` 128)) (keysExt!!((i*24+r*3+2) `mod` 128))) a [0..30]
      mixCon a i = foldl' (\acc r -> rndC acc (keysExt!!((i*24+r*3) `mod` 128)) (keysExt!!((i*24+r*3+1) `mod` 128)) (keysExt!!((i*24+r*3+2) `mod` 128))) a [0..30]
      mkCheck i =
        let fw = flagWords !! i
            target = mixCon fw i
            sym = mixSym (InputWord (fromIntegral i)) i
        in Eq sym (VNum target)
      checks = map mkCheck [0..nWords-1]
      combined = foldr1 (\a b -> IfP a b (Eq (VNum 0) (VNum 1))) checks
  in Module (Halt combined)
