module Parser.Source (runParserProgram) where

import Control.Monad (void)
import Data.Void
import Data.Char (isAlphaNum)
import Text.Megaparsec
import Text.Megaparsec.Char
import qualified Text.Megaparsec.Char.Lexer as L
import Lang.Source

sc :: Parser ()
sc = L.space space1 empty empty

lexeme :: Parser a -> Parser a
lexeme = L.lexeme sc

symbol :: String -> Parser String
symbol = L.symbol sc

parens :: Parser a -> Parser a
parens = between (symbol "(") (symbol ")")

identifier :: Parser String
identifier = lexeme $ some (satisfy isSymbolChar)

isSymbolChar :: Char -> Bool
isSymbolChar c =
  isAlphaNum c || c `elem` "+-*/<>=?!"

integer :: Parser Integer
integer = lexeme L.decimal

charLit :: Parser Char
charLit = lexeme $ between (char '\'') (char '\'') anySingle

parseProgram :: Parser Program
parseProgram = parens $ do
  symbol "module"
  defns <- many (try parseDefn)
  body  <- parseTail
  return $ Module defns body

parseDefn :: Parser Defn
parseDefn = parens $ do
  symbol "defn"
  name <- identifier
  args <- parens (many identifier)
  body <- parseTail
  return $ Defn name args body

parseTail :: Parser Tail
parseTail =
       (try parseListTail)
   <|> (TValue <$> parseValue)

parseListTail :: Parser Tail
parseListTail = parens $ do
  headSym <- identifier
  case headSym of
    "if"   -> parseIfRest
    "let"  -> parseLetRest
    "call" -> parseCallRest
    _      -> fail ("Unknown tail form: " ++ headSym)

parseIfRest :: Parser Tail
parseIfRest = do
  p  <- parsePred
  t1 <- parseTail
  t2 <- parseTail
  return $ If p t1 t2

parseLetRest :: Parser Tail
parseLetRest = do
  bindings <- parens (many parseBinding)
  body <- parseTail
  return $ Let bindings body

parseBinding :: Parser (String, Value)
parseBinding = parens $ do
  name <- identifier
  val <- parseValue
  return (name, val)

parseCallRest :: Parser Tail
parseCallRest = do
  fname <- identifier
  args  <- many parseValue
  return $ Call fname args

parsePred :: Parser Pred
parsePred = parens $ do
  headSym <- identifier
  case headSym of
    "not"     -> Not <$> parsePred
    "<"       -> Lt <$> parseValue <*> parseValue
    ">"       -> Gt <$> parseValue <*> parseValue
    "="       -> Eq <$> parseValue <*> parseValue
    "empty?"  -> Empty <$> parseValue
    "number?" -> IsNumber <$> parseValue
    _         -> fail ("Unknown predicate: " ++ headSym)

parseValue :: Parser Value
parseValue =
      parseAtomValue
  <|> parseListValue

parseAtomValue :: Parser Value
parseAtomValue =
      (VNum <$> integer)
  <|> (VChar <$> charLit)
  <|> (symbol "nil" >> return VNil)
  <|> (VVar <$> identifier)

parseListValue :: Parser Value
parseListValue = parens $ do
  headSym <- identifier
  case headSym of
    "+"    -> Add <$> parseValue <*> parseValue
    "chr"  -> Chr <$> parseValue
    "ord"  -> Ord <$> parseValue
    "cons" -> Cons <$> parseValue <*> parseValue
    "car"  -> Car <$> parseValue
    "cdr"  -> Cdr <$> parseValue
    _      -> fail ("Unknown value form: " ++ headSym)

parseEmpty = symbol "empty?" >> (Empty <$> parseValue)
parseNumber = symbol "number?" >> (IsNumber <$> parseValue)

runParserProgram :: String -> Either (ParseErrorBundle String Void) Program
runParserProgram = runParser (sc *> parseProgram <* eof) "<input>"
