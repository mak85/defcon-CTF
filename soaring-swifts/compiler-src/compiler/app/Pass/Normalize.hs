module Pass.Normalize where

import Common.Location (Location (..), Pass (..))
import Control.Monad.State
import Data.Int
import qualified Lang.Norm as T
import qualified Lang.Seq as S

-- State: next fresh temp location
type Fresh = Int64

normalize :: S.Program -> T.Program
normalize (S.Module t) = T.Module $ evalState (normalizeTail t) 0
  where
    fresh :: State Fresh Location
    fresh = do
      n <- get
      put (n + 1)
      return (Location Normalize n)

    normalizeTail :: S.Tail -> State Fresh T.Tail
    normalizeTail (S.Halt p) = T.Halt <$> normalizePred p
    normalizeTail (S.IfT p tc ta) = T.IfT <$> normalizePred p <*> normalizeTail tc <*> normalizeTail ta
    normalizeTail (S.BeginT effs tl) = do
      effs' <- mapM normalizeEffect effs
      tl' <- normalizeTail tl
      return $ T.BeginT effs' tl'
    normalizeTail (S.Loop p base recs) = do
      p' <- normalizePred p
      base' <- normalizeTail base
      recs' <- mapM normalizeEffect recs
      return $ T.Loop p' base' recs'

    -- Returns effects to compute value + the resulting Triv
    normalizeValue :: S.Value -> State Fresh ([T.Effect], T.Triv)
    normalizeValue (S.VNum n) = return ([], T.TrivNum n)
    normalizeValue (S.VLoc loc) = return ([], T.TrivLoc loc)
    normalizeValue (S.Add v1 v2) = normalizeBinOp T.SetAdd v1 v2
    normalizeValue (S.Sub v1 v2) = normalizeBinOp T.SetSub v1 v2
    normalizeValue (S.Mul v1 v2) = normalizeBinOp T.SetMul v1 v2
    normalizeValue (S.BitAnd v1 v2) = normalizeBinOp T.SetBitAnd v1 v2
    normalizeValue (S.BitXor v1 v2) = normalizeBinOp T.SetBitXor v1 v2
    normalizeValue (S.BitIor v1 v2) = normalizeBinOp T.SetBitIor v1 v2
    normalizeValue (S.ShiftL v1 v2) = normalizeBinOp T.SetShiftL v1 v2
    normalizeValue (S.ShiftR v1 v2) = normalizeBinOp T.SetShiftR v1 v2
    normalizeValue (S.IfV p vc va) = do
      p' <- normalizePred p
      (effsC, trivC) <- normalizeValue vc
      (effsA, trivA) <- normalizeValue va
      tmp <- fresh
      let effC = T.BeginE effsC (T.Set tmp trivC)
          effA = T.BeginE effsA (T.Set tmp trivA)
      return ([T.IfE p' effC effA], T.TrivLoc tmp)
    normalizeValue (S.BeginV effs v) = do
      effs' <- mapM normalizeEffect effs
      (vEffs, triv) <- normalizeValue v
      return (effs' ++ vEffs, triv)

    normalizeBinOp :: (Location -> T.Triv -> T.Effect) -> S.Value -> S.Value -> State Fresh ([T.Effect], T.Triv)
    normalizeBinOp mkOp v1 v2 = do
      (effs1, triv1) <- normalizeValue v1
      (effs2, triv2) <- normalizeValue v2
      tmp1 <- fresh
      tmp2 <- fresh
      let effs = effs1 ++ effs2 ++ [T.Set tmp1 triv1, T.Set tmp2 triv2, mkOp tmp1 (T.TrivLoc tmp2)]
      return (effs, T.TrivLoc tmp1)

    normalizePred :: S.Pred -> State Fresh T.Pred
    normalizePred (S.Not p) = T.Not <$> normalizePred p
    normalizePred (S.Lt v1 v2) = normalizeCmp T.Lt v1 v2
    normalizePred (S.Gt v1 v2) = normalizeCmp T.Gt v1 v2
    normalizePred (S.Eq v1 v2) = normalizeCmp T.Eq v1 v2
    normalizePred (S.Leq v1 v2) = normalizeCmp T.Leq v1 v2
    normalizePred (S.Geq v1 v2) = normalizeCmp T.Geq v1 v2
    normalizePred (S.IfP p pc pa) = T.IfP <$> normalizePred p <*> normalizePred pc <*> normalizePred pa
    normalizePred (S.BeginP effs p) = do
      effs' <- mapM normalizeEffect effs
      p' <- normalizePred p
      return $ T.BeginP effs' p'

    normalizeCmp :: (T.Triv -> T.Triv -> T.Pred) -> S.Value -> S.Value -> State Fresh T.Pred
    normalizeCmp mkCmp v1 v2 = do
      (effs1, triv1) <- normalizeValue v1
      (effs2, triv2) <- normalizeValue v2
      let effs = effs1 ++ effs2
          p = mkCmp triv1 triv2
      return $ if null effs then p else T.BeginP effs p

    normalizeEffect :: S.Effect -> State Fresh T.Effect
    normalizeEffect (S.Set loc v) = do
      (effs, triv) <- normalizeValue v
      let setEff = T.Set loc triv
      return $ if null effs then setEff else T.BeginE effs setEff
    normalizeEffect (S.BeginE effs eff) = do
      effs' <- mapM normalizeEffect effs
      eff' <- normalizeEffect eff
      return $ T.BeginE effs' eff'
    normalizeEffect (S.IfE p effC effA) = do
      p' <- normalizePred p
      effC' <- normalizeEffect effC
      effA' <- normalizeEffect effA
      return $ T.IfE p' effC' effA'
