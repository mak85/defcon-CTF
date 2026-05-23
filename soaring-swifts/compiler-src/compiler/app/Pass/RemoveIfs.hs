module Pass.RemoveIfs where

import Data.List.NonEmpty (NonEmpty (..), prependList, toList)
import qualified Lang.FlatBlock as S
import qualified Lang.Jumpy as T

removeIfs :: S.Program -> T.Program
removeIfs (S.Module blocks effs t) = T.Module $ effsStmts ++ tailStmts ++ blocksStmts
  where
    blocksStmts = concatMap removeIfsBlock blocks
    effsStmts = map removeIfsEffect effs
    tailStmts = toList $ removeIfsTail t

    removeIfsBlock :: S.Block -> [T.Statement]
    removeIfsBlock (S.Block label effs' tail') = (T.WithLabel label stmt) : stmts
      where
        (stmt :| stmts) = (map removeIfsEffect effs') `prependList` (removeIfsTail tail')

    removeIfsTail :: S.Tail -> (NonEmpty T.Statement)
    removeIfsTail (S.Jump label) = (T.Jump label) :| []
    removeIfsTail (S.IfT p labelC labelA) =
      T.CmpJump (removeIfsPred p) labelC :| [T.Jump labelA]

    removeIfsPred :: S.Pred -> T.Pred
    removeIfsPred (S.Eq triv1 triv2) = T.Eq (removeIfsTriv triv1) (removeIfsTriv triv2)
    removeIfsPred (S.Lt triv1 triv2) = T.Lt (removeIfsTriv triv1) (removeIfsTriv triv2)

    removeIfsEffect :: S.Effect -> T.Statement
    removeIfsEffect (S.Set loc triv) = T.Set loc (removeIfsTriv triv)
    removeIfsEffect (S.SetAdd loc triv) = T.SetAdd loc (removeIfsTriv triv)
    removeIfsEffect (S.SetSub loc triv) = T.SetSub loc (removeIfsTriv triv)
    removeIfsEffect (S.SetMul loc triv) = T.SetMul loc (removeIfsTriv triv)
    removeIfsEffect (S.SetBitAnd loc triv) = T.SetBitAnd loc (removeIfsTriv triv)
    removeIfsEffect (S.SetBitXor loc triv) = T.SetBitXor loc (removeIfsTriv triv)
    removeIfsEffect (S.SetBitIor loc triv) = T.SetBitIor loc (removeIfsTriv triv)
    removeIfsEffect (S.SetShiftL loc triv) = T.SetShiftL loc (removeIfsTriv triv)
    removeIfsEffect (S.SetShiftR loc triv) = T.SetShiftR loc (removeIfsTriv triv)

    removeIfsTriv :: S.Triv -> T.Triv
    removeIfsTriv (S.TrivLoc loc) = T.TrivLoc loc
    removeIfsTriv (S.TrivNum n) = T.TrivNum n
