module Common.Env where

-- Environment mapping keys to values
newtype Env k v = Env [(k, v)]

empty :: Env k v
empty = Env []

lookup :: Eq k => k -> Env k v -> Maybe v
lookup k (Env xs) = Prelude.lookup k xs

add :: k -> v -> Env k v -> Env k v
add k v (Env xs) = Env ((k, v) : xs)

remove :: Eq k => k -> Env k v -> Env k v
remove k (Env xs) = Env (filter ((/= k) . fst) xs)

merge :: Env k v -> Env k v -> Env k v
merge (Env xs) (Env ys) = Env (xs ++ ys)
