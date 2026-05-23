module Pass.Uniquify where

import Common.Env (Env)
import qualified Common.Env as Env
import Common.Location (Location (..), Pass (..))
import Control.Monad (forM)
import Control.Monad.State
import qualified Lang.AlphaEq as T
import qualified Lang.Source as S
import Data.Int

-- State: next fresh location index
type Fresh = Int64

uniquify :: (Eq a) => S.Program a -> T.Program
uniquify (S.Module t) = T.Module $ evalState (uniquifyTail Env.empty t) 0
  where
    fresh :: State Fresh Location
    fresh = do
      n <- get
      put (n + 1)
      return (Location Uniquify n)

    extendEnv :: (Eq a) => [(a, S.Value a)] -> Env a Location -> State Fresh (Env a Location, [(Location, T.Value)])
    extendEnv bindings env = do
      bindings' <- forM bindings $ \(name, val) -> do
        loc <- fresh
        val' <- uniquifyValue env val
        return (name, loc, val')
      let env' = foldr (\(name, loc, _) e -> Env.add name loc e) env bindings'
      let tBindings = map (\(_, loc, val') -> (loc, val')) bindings'
      return (env', tBindings)

    uniquifyTail :: (Eq a) => Env a Location -> S.Tail a -> State Fresh T.Tail
    uniquifyTail env (S.Halt p) = T.Halt <$> uniquifyPred env p
    uniquifyTail env (S.IfT p tc ta) = T.IfT <$> uniquifyPred env p <*> uniquifyTail env tc <*> uniquifyTail env ta
    uniquifyTail env (S.LetT bindings body) = do
      (env', bindings') <- extendEnv bindings env
      body' <- uniquifyTail env' body
      return $ T.LetT bindings' body'
    uniquifyTail env (S.LetLoop bindings p base rec) = do
      (env', bindings') <- extendEnv bindings env
      p' <- uniquifyPred env' p
      base' <- uniquifyTail env' base
      rec' <- mapM (uniquifyValue env') rec
      return $ T.LetLoop bindings' p' base' rec'

    uniquifyValue :: (Eq a) => Env a Location -> S.Value a -> State Fresh T.Value
    uniquifyValue env (S.Identifier x) = case Env.lookup x env of
      Just loc -> return $ T.VLoc loc
      Nothing -> error "Unbound identifier"
    uniquifyValue _ (S.VNum n) = return $ T.VNum n
    uniquifyValue _ (S.InputWord n) = return $ T.VLoc (Location Input (n * 8))
    uniquifyValue env (S.Add v1 v2) = T.Add <$> uniquifyValue env v1 <*> uniquifyValue env v2
    uniquifyValue env (S.Sub v1 v2) = T.Sub <$> uniquifyValue env v1 <*> uniquifyValue env v2
    uniquifyValue env (S.Mul v1 v2) = T.Mul <$> uniquifyValue env v1 <*> uniquifyValue env v2
    uniquifyValue env (S.BitAnd v1 v2) = T.BitAnd <$> uniquifyValue env v1 <*> uniquifyValue env v2
    uniquifyValue env (S.BitXor v1 v2) = T.BitXor <$> uniquifyValue env v1 <*> uniquifyValue env v2
    uniquifyValue env (S.BitIor v1 v2) = T.BitIor <$> uniquifyValue env v1 <*> uniquifyValue env v2
    uniquifyValue env (S.ShiftL v1 v2) = T.ShiftL <$> uniquifyValue env v1 <*> uniquifyValue env v2
    uniquifyValue env (S.ShiftR v1 v2) = T.ShiftR <$> uniquifyValue env v1 <*> uniquifyValue env v2
    uniquifyValue env (S.IfV p vc va) = T.IfV <$> uniquifyPred env p <*> uniquifyValue env vc <*> uniquifyValue env va
    uniquifyValue env (S.LetV bindings body) = do
      (env', bindings') <- extendEnv bindings env
      body' <- uniquifyValue env' body
      return $ T.LetV bindings' body'

    uniquifyPred :: (Eq a) => Env a Location -> S.Pred a -> State Fresh T.Pred
    uniquifyPred env (S.Not p) = T.Not <$> uniquifyPred env p
    uniquifyPred env (S.Lt v1 v2) = T.Lt <$> uniquifyValue env v1 <*> uniquifyValue env v2
    uniquifyPred env (S.Gt v1 v2) = T.Gt <$> uniquifyValue env v1 <*> uniquifyValue env v2
    uniquifyPred env (S.Eq v1 v2) = T.Eq <$> uniquifyValue env v1 <*> uniquifyValue env v2
    uniquifyPred env (S.Leq v1 v2) = T.Leq <$> uniquifyValue env v1 <*> uniquifyValue env v2
    uniquifyPred env (S.Geq v1 v2) = T.Geq <$> uniquifyValue env v1 <*> uniquifyValue env v2
    uniquifyPred env (S.IfP p pc pa) = T.IfP <$> uniquifyPred env p <*> uniquifyPred env pc <*> uniquifyPred env pa
    uniquifyPred env (S.LetP bindings body) = do
      (env', bindings') <- extendEnv bindings env
      body' <- uniquifyPred env' body
      return $ T.LetP bindings' body'
