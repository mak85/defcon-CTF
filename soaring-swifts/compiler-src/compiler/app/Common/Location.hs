module Common.Location where
import Data.Int

data Location = Location Pass Int64
  deriving (Show, Eq)

data Label
  = Label Pass Int64
  | Success
  | Failure
  deriving (Show, Eq)

data Pass = Input | Uniquify | Sequentialize | Normalize | ExposeBlocks
  deriving (Show, Eq)
