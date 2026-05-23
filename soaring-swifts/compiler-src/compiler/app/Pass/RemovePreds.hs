module Pass.RemovePreds where

import Common.Constants
import Common.Env (Env)
import qualified Common.Env as Env
import qualified Common.Location as C
import Control.Monad.State
import Data.Int
import qualified Lang.Jumpless as S
import qualified Lang.Predless as T

data RemovePredsState = RemovePredsState
  { freshLabel :: Int64,
    freshLoc :: Int64,
    labelEnv :: Env C.Label T.Label,
    locEnv :: Env C.Location T.Location
  }

type RemovePreds a = State RemovePredsState a

-- BasePointer + 0 is reserved
initState :: RemovePredsState
initState = RemovePredsState 0 1 Env.empty Env.empty

removePreds :: S.Program -> T.Program
removePreds (S.Module stmts) = T.Module $ evalState (removePredsStatements stmts) initState

removePredsStatements :: [S.Statement] -> RemovePreds [T.Statement]
removePredsStatements stmts = concat <$> mapM removePredsStatement stmts

removePredsStatement :: S.Statement -> RemovePreds [T.Statement]
removePredsStatement (S.Set loc triv) = do
  loc' <- removePredsLocation loc
  triv' <- removePredsTriv triv
  return [T.Set loc' triv']
removePredsStatement (S.SetAdd loc triv) = do
  loc' <- removePredsLocation loc
  triv' <- removePredsTriv triv
  return [T.SetAdd loc' triv']
removePredsStatement (S.SetSub loc triv) = do
  loc' <- removePredsLocation loc
  triv' <- removePredsTriv triv
  return [T.SetSub loc' triv']
removePredsStatement (S.SetMul loc triv) = do
  loc' <- removePredsLocation loc
  triv' <- removePredsTriv triv
  return [T.SetMul loc' triv']
removePredsStatement (S.SetBitNot loc) = do
  loc' <- removePredsLocation loc
  return [T.SetBitNot loc']
removePredsStatement (S.SetBitAnd loc triv) = do
  loc' <- removePredsLocation loc
  triv' <- removePredsTriv triv
  return [T.SetBitAnd loc' triv']
removePredsStatement (S.SetBitXor loc triv) = do
  loc' <- removePredsLocation loc
  triv' <- removePredsTriv triv
  return [T.SetBitXor loc' triv']
removePredsStatement (S.SetBitIor loc triv) = do
  loc' <- removePredsLocation loc
  triv' <- removePredsTriv triv
  return [T.SetBitIor loc' triv']
removePredsStatement (S.SetShiftL loc triv) = do
  loc' <- removePredsLocation loc
  triv' <- removePredsTriv triv
  return [T.SetShiftL loc' triv']
removePredsStatement (S.SetShiftR loc triv) = do
  loc' <- removePredsLocation loc
  triv' <- removePredsTriv triv
  return [T.SetShiftR loc' triv']

removePredsStatement (S.Enable label) = do
  label' <- (removePredsLabel label)
  return $
    [(T.LoadAddr T.R8 T.RealBase)]
      ++ (eqCheck (T.TrivNum (labelToInt label')) (T.TrivLoc (T.Rel T.R8 0)))
      ++ [ (T.SetBitNot (T.Reg T.CompareResultRegister)),
           ( T.SetBitAnd
               (T.Reg T.BasePointerRegister)
               (T.TrivLoc (T.Reg T.CompareResultRegister))
           )
         ]

removePredsStatement (S.Disable label) = do
  label' <- (removePredsLabel label)
  return $
    [ (T.Set (T.Rel T.BasePointerRegister 0) (T.TrivNum (labelToInt label'))),
      (T.LoadAddr T.BasePointerRegister T.FakeBase)
    ]

removePredsStatement (S.CmpDisable p label) = do
  label' <- (removePredsLabel label)
  p' <- (removePredsPred p)
  return $
    p'
      ++ [ (T.Set (T.Rel T.BasePointerRegister 0) (T.TrivNum (labelToInt label'))),
           ( T.SetBitIor
               (T.Reg T.BasePointerRegister)
               (T.TrivLoc (T.Reg T.CompareResultRegister))
           )
         ]

removePredsTriv :: S.Triv -> RemovePreds T.Triv
removePredsTriv (S.TrivLoc loc) = T.TrivLoc <$> removePredsLocation loc
removePredsTriv (S.TrivNum n) = return $ T.TrivNum n

removePredsLocation :: C.Location -> RemovePreds T.Location
removePredsLocation (C.Location C.Input n) =
  -- Input locations use InputBaseRegister with byte offset
  return $ T.Rel T.InputBaseRegister n
removePredsLocation loc = do
  st <- get
  case Env.lookup loc (locEnv st) of
    Just loc' -> return loc'
    Nothing -> do
      let n = freshLoc st
      let loc' = T.Rel T.BasePointerRegister (n * 8)
      put st {freshLoc = n + 1, locEnv = Env.add loc loc' (locEnv st)}
      return loc'

removePredsLabel :: C.Label -> RemovePreds T.Label
removePredsLabel C.Success = return T.Success
removePredsLabel C.Failure = return T.Failure
removePredsLabel label = do
  st <- get
  case Env.lookup label (labelEnv st) of
    Just label' -> return label'
    Nothing -> do
      let n = freshLabel st
      let label' = T.Code n
      put st {freshLabel = n + 1, labelEnv = Env.add label label' (labelEnv st)}
      return label'

removePredsPred :: S.Pred -> RemovePreds [T.Statement]
removePredsPred (S.Lt triv1 triv2) = do
  triv1' <- (removePredsTriv triv1)
  triv2' <- (removePredsTriv triv2)
  return $ ltCheck triv1' triv2'
removePredsPred (S.Eq triv1 triv2) = do
  triv1' <- (removePredsTriv triv1)
  triv2' <- (removePredsTriv triv2)
  return $ eqCheck triv1' triv2'

-- r9 <- triv1 `xor` triv2
-- r9 <- LZCNT r9
-- cl <- (32 - r9)
-- r10 <- shr r9 cl
-- r10 <- and r10 ~1
-- CompareResultRegister <- shl r10 x
-- (RealBase and FakeBase should only differ in the x-th bit position)
eqCheck :: T.Triv -> T.Triv -> [T.Statement]
eqCheck triv1 triv2 =
  [ T.Set (T.Reg T.R9) triv1,
    T.SetBitXor (T.Reg T.R9) triv2,
    T.BitScanReverse T.RCX (T.Reg T.R9),
    T.SetShiftR (T.Reg T.R9) (T.TrivLoc (T.Reg T.CL)),
    T.SetBitXor (T.Reg T.R9) (T.TrivNum 1),
    T.SetShiftL (T.Reg T.R9) (T.TrivNum baseBitDiff),
    T.Set (T.Reg T.CompareResultRegister) (T.TrivLoc (T.Reg T.R9))
  ]

-- r9 <- triv1 `xor` triv2
-- r9 <- LZCNT r9
-- cl <- (32 - r9)
-- r10 <- shr triv1 cl
-- r10 <- and r10 ~1
-- CompareResultRegister <- shl r10 x
-- (RealBase and FakeBase should only differ in the x-th bit position)
ltCheck :: T.Triv -> T.Triv -> [T.Statement]
ltCheck triv1 triv2 =
  [ T.Set (T.Reg T.R9) triv2,
    T.Set (T.Reg T.R10) (T.TrivLoc (T.Reg T.R9)),
    T.SetBitXor (T.Reg T.R9) triv1,
    T.BitScanReverse T.RCX (T.Reg T.R9),
    T.SetShiftR (T.Reg T.R9) (T.TrivLoc (T.Reg T.CL)),
    T.SetShiftR (T.Reg T.R10) (T.TrivLoc (T.Reg T.CL)),
    T.SetBitAnd (T.Reg T.R10) (T.TrivLoc (T.Reg T.R9)),
    T.SetShiftL (T.Reg T.R10) (T.TrivNum baseBitDiff),
    T.Set (T.Reg T.CompareResultRegister) (T.TrivLoc (T.Reg T.R10))
  ]

labelToInt :: T.Label -> Int64
labelToInt (T.Code n) = n
labelToInt T.RealBase = realBase
labelToInt T.FakeBase = fakeBase
labelToInt T.Success = successLabel
labelToInt T.Failure = failureLabel
