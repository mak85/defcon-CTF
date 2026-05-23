module Main where

import Lang.Source
import Pass.EmbedRuntime
import Pass.ExposeBlocks
import Pass.FlattenBegins
import Pass.GenerateX64
import Pass.Normalize
import Pass.RemoveIfs
import Pass.RemoveJumps
import Pass.RemovePreds
import Pass.Sequentialize
import Pass.Uniquify
import Data.Int (Int64)
import System.Random

import Private.FlagChecker

compiler :: RandomGen g => Eq a => g -> Program a -> String
compiler _ p = unlines $
  embedRuntime $
  generateX64 $
  removePreds $
  removeJumps $
  removeIfs $
  flattenBegins $
  exposeBlocks $
  normalize $
  sequentialize $
  uniquify p

deriveKeys :: Int -> [Int64]
deriveKeys seed = take 16 $ randoms (mkStdGen seed) :: [Int64]

main :: IO ()
main = do
  flag <- getLine
  seedStr <- getLine
  let seed = read seedStr
      keys = deriveKeys seed
      gen = mkStdGen seed
  putStrLn $ compiler gen $ makeFlagChecker keys flag
