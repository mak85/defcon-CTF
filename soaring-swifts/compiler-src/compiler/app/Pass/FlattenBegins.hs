module Pass.FlattenBegins where

import qualified Lang.Block as S
import qualified Lang.FlatBlock as T

flattenBegins :: S.Program -> T.Program
flattenBegins (S.Module blocks tail) = T.Module blocks' entryEffs entryTail
  where
    blocks' = map flattenBlock blocks
    (entryEffs, entryTail) = flattenTail tail
    flattenTriv :: S.Triv -> T.Triv
    flattenTriv (S.TrivLoc loc) = T.TrivLoc loc
    flattenTriv (S.TrivNum n) = T.TrivNum n

    -- Flatten a block: collect effects from tail
    flattenBlock :: S.Block -> T.Block
    flattenBlock (S.Block label tail) = T.Block label effs tail'
      where (effs, tail') = flattenTail tail

    -- Flatten a tail: returns (accumulated effects, final tail)
    flattenTail :: S.Tail -> ([T.Effect], T.Tail)
    flattenTail (S.Jump label) = ([], T.Jump label)
    flattenTail (S.IfT pred labelT labelF) = (predEffs, T.IfT pred' labelT labelF)
      where (predEffs, pred') = flattenPred pred
    flattenTail (S.BeginT effs tail) = (flattenEffects effs ++ tailEffs, tail')
      where (tailEffs, tail') = flattenTail tail

    -- Flatten a predicate: returns (hoisted effects, flat predicate)
    flattenPred :: S.Pred -> ([T.Effect], T.Pred)
    flattenPred (S.Lt t1 t2) = ([], T.Lt (flattenTriv t1) (flattenTriv t2))
    flattenPred (S.Eq t1 t2) = ([], T.Eq (flattenTriv t1) (flattenTriv t2))
    flattenPred (S.BeginP effs p) = (flattenEffects effs ++ effs', p')
      where (effs', p') = flattenPred p

    -- Flatten an effect: returns list of flat effects
    flattenEffect :: S.Effect -> [T.Effect]
    flattenEffect (S.Set loc triv) = [T.Set loc (flattenTriv triv)]
    flattenEffect (S.SetAdd loc triv) = [T.SetAdd loc (flattenTriv triv)]
    flattenEffect (S.SetSub loc triv) = [T.SetSub loc (flattenTriv triv)]
    flattenEffect (S.SetMul loc triv) = [T.SetMul loc (flattenTriv triv)]
    flattenEffect (S.SetBitAnd loc triv) = [T.SetBitAnd loc (flattenTriv triv)]
    flattenEffect (S.SetBitXor loc triv) = [T.SetBitXor loc (flattenTriv triv)]
    flattenEffect (S.SetBitIor loc triv) = [T.SetBitIor loc (flattenTriv triv)]
    flattenEffect (S.SetShiftL loc triv) = [T.SetShiftL loc (flattenTriv triv)]
    flattenEffect (S.SetShiftR loc triv) = [T.SetShiftR loc (flattenTriv triv)]
    flattenEffect (S.BeginE effs eff) = flattenEffects effs ++ flattenEffect eff

    -- Flatten a list of effects
    flattenEffects :: [S.Effect] -> [T.Effect]
    flattenEffects effs = concatMap flattenEffect effs
