module Pass.RemoveJumps where

import qualified Lang.Jumpless as T
import qualified Lang.Jumpy as S

removeJumps :: S.Program -> T.Program
removeJumps (S.Module stmts) = T.Module $ concatMap removeJumpsStatement stmts
  where
    removeJumpsStatement :: S.Statement -> [T.Statement]
    removeJumpsStatement (S.Set loc triv) = [T.Set loc (removeJumpsTriv triv)]
    removeJumpsStatement (S.SetAdd loc triv) = [T.SetAdd loc (removeJumpsTriv triv)]
    removeJumpsStatement (S.SetSub loc triv) = [T.SetSub loc (removeJumpsTriv triv)]
    removeJumpsStatement (S.SetMul loc triv) = [T.SetMul loc (removeJumpsTriv triv)]
    removeJumpsStatement (S.SetBitAnd loc triv) = [T.SetBitAnd loc (removeJumpsTriv triv)]
    removeJumpsStatement (S.SetBitXor loc triv) = [T.SetBitXor loc (removeJumpsTriv triv)]
    removeJumpsStatement (S.SetBitIor loc triv) = [T.SetBitIor loc (removeJumpsTriv triv)]
    removeJumpsStatement (S.SetShiftL loc triv) = [T.SetShiftL loc (removeJumpsTriv triv)]
    removeJumpsStatement (S.SetShiftR loc triv) = [T.SetShiftR loc (removeJumpsTriv triv)]
    removeJumpsStatement (S.WithLabel label stmt) = (T.Enable label) : (removeJumpsStatement stmt)
    removeJumpsStatement (S.Jump label) = [T.Disable label]
    removeJumpsStatement (S.CmpJump p label) = [T.CmpDisable (removeJumpsPred p) label]

    removeJumpsPred :: S.Pred -> T.Pred
    removeJumpsPred (S.Eq triv1 triv2) = T.Eq (removeJumpsTriv triv1) (removeJumpsTriv triv2)
    removeJumpsPred (S.Lt triv1 triv2) = T.Lt (removeJumpsTriv triv1) (removeJumpsTriv triv2)

    removeJumpsTriv :: S.Triv -> T.Triv
    removeJumpsTriv (S.TrivLoc loc) = T.TrivLoc loc
    removeJumpsTriv (S.TrivNum n) = T.TrivNum n
