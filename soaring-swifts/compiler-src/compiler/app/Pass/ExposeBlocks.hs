module Pass.ExposeBlocks where

import Common.Location (Label (..), Location (..), Pass (..))
import Control.Monad.State
import qualified Lang.Block as T
import qualified Lang.Norm as S
import Data.Int

-- State: next fresh label, next fresh location, and accumulated blocks
data ExposeState = ExposeState
  { nextLabel :: Int64,
    nextLoc :: Int64,
    blocks :: [T.Block]
  }

type Expose a = State ExposeState a

exposeBlocks :: S.Program -> T.Program
exposeBlocks (S.Module t) = T.Module (blocks finalState) tail'
  where
    (tail', finalState) = runState (exposeTail t) initState
    initState = ExposeState {nextLabel = 0, nextLoc = 0, blocks = []}
    freshLabel :: Expose Label
    freshLabel = do
      st <- get
      let n = nextLabel st
      put st {nextLabel = n + 1}
      return (Label ExposeBlocks n)

    freshLocation :: Expose Location
    freshLocation = do
      st <- get
      let n = nextLoc st
      put st {nextLoc = n + 1}
      return (Location ExposeBlocks n)

    emitBlock :: Label -> T.Tail -> Expose ()
    emitBlock lbl tl = do
      st <- get
      put st {blocks = blocks st ++ [T.Block lbl tl]}

    exposeTriv :: S.Triv -> T.Triv
    exposeTriv (S.TrivLoc loc) = T.TrivLoc loc
    exposeTriv (S.TrivNum n) = T.TrivNum n

    -- Expose a predicate given then/else labels, returns branching tail
    exposePred :: S.Pred -> Label -> Label -> Expose T.Tail
    exposePred (S.Not p) thenL elseL = exposePred p elseL thenL
    exposePred (S.Lt t1 t2) thenL elseL =
      return $ T.IfT (T.Lt (exposeTriv t1) (exposeTriv t2)) thenL elseL
    exposePred (S.Gt t1 t2) thenL elseL =
      return $ T.IfT (T.Lt (exposeTriv t2) (exposeTriv t1)) thenL elseL  -- swap operands
    exposePred (S.Eq t1 t2) thenL elseL =
      return $ T.IfT (T.Eq (exposeTriv t1) (exposeTriv t2)) thenL elseL
    exposePred (S.Leq t1 t2) thenL elseL = exposePred (S.Gt t1 t2) elseL thenL  -- not(gt) = leq
    exposePred (S.Geq t1 t2) thenL elseL = exposePred (S.Lt t1 t2) elseL thenL  -- not(lt) = geq
    exposePred (S.IfP p pc pa) thenL elseL = do
      labelC <- freshLabel
      labelA <- freshLabel
      tailC <- exposePred pc thenL elseL
      tailA <- exposePred pa thenL elseL
      emitBlock labelC tailC
      emitBlock labelA tailA
      exposePred p labelC labelA
    exposePred (S.BeginP effs p) thenL elseL =
      exposeEffectsK effs (exposePred p thenL elseL)

    -- Expose a single effect with CPS: takes continuation, returns tail
    exposeEffectK :: S.Effect -> Expose T.Tail -> Expose T.Tail
    exposeEffectK (S.Set loc triv) k = do
      tail'' <- k
      return $ T.BeginT [T.Set loc (exposeTriv triv)] tail''
    exposeEffectK (S.SetAdd loc triv) k = do
      tail'' <- k
      return $ T.BeginT [T.SetAdd loc (exposeTriv triv)] tail''
    exposeEffectK (S.SetSub loc triv) k = do
      tail'' <- k
      return $ T.BeginT [T.SetSub loc (exposeTriv triv)] tail''
    exposeEffectK (S.SetMul loc triv) k = do
      tail'' <- k
      return $ T.BeginT [T.SetMul loc (exposeTriv triv)] tail''
    exposeEffectK (S.SetBitAnd loc triv) k = do
      tail'' <- k
      return $ T.BeginT [T.SetBitAnd loc (exposeTriv triv)] tail''
    exposeEffectK (S.SetBitXor loc triv) k = do
      tail'' <- k
      return $ T.BeginT [T.SetBitXor loc (exposeTriv triv)] tail''
    exposeEffectK (S.SetBitIor loc triv) k = do
      tail'' <- k
      return $ T.BeginT [T.SetBitIor loc (exposeTriv triv)] tail''
    exposeEffectK (S.SetShiftL loc triv) k = do
      tail'' <- k
      return $ T.BeginT [T.SetShiftL loc (exposeTriv triv)] tail''
    exposeEffectK (S.SetShiftR loc triv) k = do
      tail'' <- k
      return $ T.BeginT [T.SetShiftR loc (exposeTriv triv)] tail''
    exposeEffectK (S.BeginE effs eff) k = exposeEffectsK effs (exposeEffectK eff k)
    exposeEffectK (S.IfE p ec ea) k = do
      -- Create join block for continuation
      joinLabel <- freshLabel
      joinTail <- k
      emitBlock joinLabel joinTail
      -- Each branch jumps to join after its effect
      labelC <- freshLabel
      labelA <- freshLabel
      tailC <- exposeEffectK ec (return $ T.Jump joinLabel)
      tailA <- exposeEffectK ea (return $ T.Jump joinLabel)
      emitBlock labelC tailC
      emitBlock labelA tailA
      exposePred p labelC labelA

    -- Expose a list of effects with CPS: takes continuation, returns tail
    exposeEffectsK :: [S.Effect] -> Expose T.Tail -> Expose T.Tail
    exposeEffectsK [] k = k
    exposeEffectsK (eff : effs) k = exposeEffectK eff (exposeEffectsK effs k)

    -- Main entry: expose a tail
    exposeTail :: S.Tail -> Expose T.Tail
    exposeTail (S.Halt p) = exposePred p Success Failure
    exposeTail (S.IfT p tc ta) = do
      labelC <- freshLabel
      labelA <- freshLabel
      tailC <- exposeTail tc
      tailA <- exposeTail ta
      emitBlock labelC tailC
      emitBlock labelA tailA
      exposePred p labelC labelA
    exposeTail (S.BeginT effs t) = exposeEffectsK effs (exposeTail t)
    exposeTail (S.Loop p base recs) = do
      loopLabel <- freshLabel
      baseLabel <- freshLabel
      recLabel <- freshLabel
      -- Base case: when predicate is true
      baseTail <- exposeTail base
      -- Recursive case: run effects, jump back to loop
      recTail <- exposeEffectsK recs (return $ T.Jump loopLabel)
      -- Loop header: check predicate, branch to base or rec
      loopTail <- exposePred p baseLabel recLabel
      emitBlock loopLabel loopTail
      emitBlock baseLabel baseTail
      emitBlock recLabel recTail
      -- Entry point: jump to loop header
      return $ T.Jump loopLabel
