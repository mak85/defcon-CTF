module Pass.Sequentialize where

import Common.Location (Location (..), Pass (..))
import Control.Monad.State
import qualified Lang.AlphaEq as S
import qualified Lang.Seq as T
import Data.Int

type Fresh = Int64

sequentialize :: S.Program -> T.Program
sequentialize (S.Module t) = T.Module $ evalState (sequentializeTail t) 0
  where
    fresh :: State Fresh Location
    fresh = do
      n <- get
      put (n + 1)
      return (Location Sequentialize n)

    sequentializeTail :: S.Tail -> State Fresh T.Tail
    sequentializeTail (S.Halt p) = return $ T.Halt (sequentializePred p)
    sequentializeTail (S.IfT p tailc taila) = do
      tailc' <- sequentializeTail tailc
      taila' <- sequentializeTail taila
      return $ T.IfT (sequentializePred p) tailc' taila'
    sequentializeTail (S.LetLoop bindings p base rec) = do
      -- Create temp locations for each binding
      temps <- mapM (const fresh) bindings
      let effects = map (\(loc, v) -> T.Set loc (sequentializeValue v)) bindings
      let p' = sequentializePred p
      base' <- sequentializeTail base
      -- First compute into temps, then copy to original locations
      let recTemps = zipWith (\tmp (_, v) -> T.Set tmp (sequentializeValue v)) temps (zip bindings rec)
      let recCopies = zipWith (\tmp (loc, _) -> T.Set loc (T.VLoc tmp)) temps bindings
      let rec' = recTemps ++ recCopies
      return $ T.BeginT effects $ T.Loop p' base' rec'
    sequentializeTail (S.LetT bindings body) = do
      body' <- sequentializeTail body
      let effects = map (\(loc, v) -> T.Set loc (sequentializeValue v)) bindings
      return $ T.BeginT effects body'

    sequentializePred :: S.Pred -> T.Pred
    sequentializePred (S.Not p) = T.Not $ sequentializePred p
    sequentializePred (S.Lt v1 v2) = T.Lt (sequentializeValue v1) (sequentializeValue v2)
    sequentializePred (S.Gt v1 v2) = T.Gt (sequentializeValue v1) (sequentializeValue v2)
    sequentializePred (S.Eq v1 v2) = T.Eq (sequentializeValue v1) (sequentializeValue v2)
    sequentializePred (S.Leq v1 v2) = T.Leq (sequentializeValue v1) (sequentializeValue v2)
    sequentializePred (S.Geq v1 v2) = T.Geq (sequentializeValue v1) (sequentializeValue v2)
    sequentializePred (S.IfP p pc pa) = T.IfP (sequentializePred p) (sequentializePred pc) (sequentializePred pa)
    sequentializePred (S.LetP bindings body) = T.BeginP effects $ sequentializePred body
      where
        effects = map (\(loc, v) -> T.Set loc (sequentializeValue v)) bindings

    sequentializeValue :: S.Value -> T.Value
    sequentializeValue (S.VLoc loc) = T.VLoc loc
    sequentializeValue (S.VNum n) = T.VNum n
    sequentializeValue (S.Add v1 v2) = T.Add (sequentializeValue v1) (sequentializeValue v2)
    sequentializeValue (S.Sub v1 v2) = T.Sub (sequentializeValue v1) (sequentializeValue v2)
    sequentializeValue (S.Mul v1 v2) = T.Mul (sequentializeValue v1) (sequentializeValue v2)
    sequentializeValue (S.BitAnd v1 v2) = T.BitAnd (sequentializeValue v1) (sequentializeValue v2)
    sequentializeValue (S.BitXor v1 v2) = T.BitXor (sequentializeValue v1) (sequentializeValue v2)
    sequentializeValue (S.BitIor v1 v2) = T.BitIor (sequentializeValue v1) (sequentializeValue v2)
    sequentializeValue (S.ShiftL v1 v2) = T.ShiftL (sequentializeValue v1) (sequentializeValue v2)
    sequentializeValue (S.ShiftR v1 v2) = T.ShiftR (sequentializeValue v1) (sequentializeValue v2)
    sequentializeValue (S.IfV p vc va) = T.IfV (sequentializePred p) (sequentializeValue vc) (sequentializeValue va)
    sequentializeValue (S.LetV bindings body) = T.BeginV effects $ sequentializeValue body
      where
        effects = map (\(loc, v) -> T.Set loc (sequentializeValue v)) bindings
