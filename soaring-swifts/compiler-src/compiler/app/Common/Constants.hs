module Common.Constants where

import Data.Int
import Data.Word
import Data.Bits (setBit)
import Numeric (showHex)

-- RealBase and FakeBase differ only in this bit position
baseBitDiff :: Int64
baseBitDiff = 30

-- Base addresses for branchless control flow
realBase :: Int64
realBase = 0xbeef000

fakeBase :: Int64
fakeBase = setBit realBase (fromIntegral baseBitDiff)

-- Format as hex for assembly output
realBaseHex :: String
realBaseHex = "0x" ++ showHex realBase ""

fakeBaseHex :: String
fakeBaseHex = "0x" ++ showHex fakeBase ""

-- Special label values for program termination
successLabel :: Int64
successLabel = 0x0f1a5000

failureLabel :: Int64
failureLabel = 0x0eadf1a5

successLabelHex :: String
successLabelHex = "0x" ++ showHex successLabel ""

failureLabelHex :: String
failureLabelHex = "0x" ++ showHex failureLabel ""
