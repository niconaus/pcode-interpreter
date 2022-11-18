{-|
Module      : PCode
Description : Ghidra P-Code language definitions
Copyright   : (c) Nico Naus, 2022
Maintainer  : niconaus@vt.edu
Stability   : experimental
This module defines the datatypes and translation of Ghidra P-Code
-}
module Parser where

import qualified Data.Map as M
import Data.Maybe ( fromMaybe )
import Data.List ( foldl', elemIndex )
import Text.ParserCombinators.Parsec
import Types
import Data.Word ( Word8 )
import Text.Hex ( decodeHex )
import qualified Data.ByteString as BS
import qualified Data.Text as T

runParse :: IO ()
runParse = do
  s <- readFile "tests/nearestPrime.txt"
  case parse pFile "(unknown)" s of
    Right x -> do
                putStrLn $ prettyPF $ fst x
                --putStrLn $ show $ snd x
                return ()
    Left er -> do
      print er
      return ()
-- Parser stuff

pFile :: GenParser Char st (PCode,Mem)
pFile = do
  prog <- M.fromList <$> many1 (try pFunction)
  _    <- string "MEMORY\n"
  mem  <- M.fromList <$> many1 (try pMemory) <* eof
  return (prog,mem)

pMemory :: GenParser Char st (Addr,Word8)
pMemory = do
  a <- pHex' 8 <$> many1 (oneOf "0123456789abcdef") <* char ' '
  w <- toEnum <$> (read <$> many1 digit) <* char '\n'
  return (a,w)

pFunction :: GenParser Char st (Fname,PBlocks)
pFunction = do
  name <- many1 (noneOf "\n") <* char '\n'  -- reads the function name
  let prefix = if take 4 name == "EXT_" then "EXT_" else ""
  addr <- pHex' 8 <$> many1 (oneOf "0123456789abcdef") <* char '\n' -- reads the HEX address that the function is stored at
  block <- many1 (try pInstr) -- parse the first block manually, since we consumed its address
  blocks <- pBlocks
  return (addr, M.insert addr block blocks)

-- gets the first address as an integer input, since it is consumed by pFunction
pBlocks :: GenParser Char st PBlocks
pBlocks = do
  result <- many $ try pEntry
  return (M.fromList result)


pEntry :: GenParser Char st (Addr,PBlock)
pEntry = do
  addr <- pAddress
  block <- many1 (try pInstr)
  return (addr,block)

pAddress :: GenParser Char st Addr
pAddress = pHex' 8 <$> many1 (oneOf "0123456789abcdef") <* many (noneOf "\n") <* char '\n'

pInstr :: GenParser Char st PInstr
pInstr = do
  try pStore <|> try pExtCall <|> try pBr <|> try pInstr1m <|> try pInstr11 <|> try pPAss

pPAss :: GenParser Char st PInstr
pPAss = do
  node <- pVarNode <* space
  PAss node <$> pOp

pStore :: GenParser Char st PInstr
pStore = do
  _ <- string " ---  "
  instr <- choice $ map (\(x,y) -> try $ string x *> return y) [("STORE", STORE),("CBRANCH",CBRANCH)]
  node1 <- string " " *> pVarNode
  node2 <- string " , "*> pVarNode
  node3 <- (string " , "*> pVarNode) <* char '\n'
  return $ instr node1 node2 node3

pBr :: GenParser Char st PInstr
pBr = do
    _ <- string " ---  "
    instr <- choice $ map (\(x,y) -> try $ string x *> return y) [("BRANCHIND",BRANCHIND),("BRANCH*",BRANCH),("BRANCH",BRANCH)]
    node <- space *> pVarNode <* char '\n'
    return $ instr node

pInstr1m :: GenParser Char st PInstr
pInstr1m = do
    _ <- string " ---  "
    instr <- choice $ map (\(x,y) -> try $ string x *> return y) [("RETURN",RETURN)]
    _ <- space
    node0 <- pVarNode
    node1 <- choice [Just <$> (string " , "*> try pVarNode),return Nothing]
    _ <- char '\n'
    return $ instr node0 node1

  -- Parses instructions of the form: CODE NODE [NODE]
pInstr11 :: GenParser Char st PInstr
pInstr11 = do
  constructor <- try (string " ---  " *> return Do) <|> try ( PCAss <$> (pVarNode <* space))
  instr <- choice $ map (try . string)["CALLIND ","CALLOTHER ","CALL "]
  node <- pVarNode
  nodes <- many (try (string " , " *> pVarNode)) <* char '\n'
  return $ constructor $ match instr node nodes
    where
      match "CALL " = CALL
      match "CALLIND " = CALLIND
      match "CALLOTHER " = CALLOTHER
      match x = error $ "this should not happen. pInstr1: " ++ show x

pExtCall :: GenParser Char st PInstr
pExtCall = do
    _ <- string " ---  "
    name <- string "EXTCALL " *> many1 (noneOf "\n") <* char '\n'
    return $ Do $ EXTCALL name

pOp :: GenParser Char st POp
pOp = choice $ map try [pInstr1,pInstr3,pInstrMult,pInstrStore]

pInstr1 :: GenParser Char st POp
pInstr1 = do
    instr <- choice $ map (\(x,y) -> try $ string x *> return y) [("INT2FLOAT",INT2FLOAT)
                                                                 ,("FLOAT2FLOAT",FLOAT2FLOAT),("FLOAT_NEG",FLOAT_NEG)
                                                                 ,("COPY",COPY),("POPCOUNT",POPCOUNT)
                                                                 ,("BOOL_NEGATE",BOOL_NEGATE)
                                                                 ,("INT_ZEXT",INT_ZEXT),("INT_SEXT",INT_SEXT)
                                                                 ,("TRUNC",TRUNC),("POPCOUNT",POPCOUNT)
                                                                 ,("INT_NEGATE",INT_NEGATE),("INT_2COMP",INT_2COMP)
                                                                 ,("CAST",CAST),("FLOAT_SQRT",FLOAT_SQRT)]
    _ <- space
    node <- pVarNode <* char '\n'
    return $ instr node

pInstrStore :: GenParser Char st POp
pInstrStore = do
  instr <- choice $ map (\(x,y) -> try $ string x *> return y) [("PTRADD",PTRADD)]
  node1 <- string " " *> pVarNode
  node2 <- string " , "*> pVarNode
  node3 <- (string " , "*> pVarNode) <* char '\n'
  return $ instr node1 node2 node3

-- Parses instructions of the form: CODE NODE [NODE]
pInstrMult :: GenParser Char st POp
pInstrMult = do
  _ <- string "MULTIEQUAL" <* space
  node <- pVarNode
  lab <- string " , " *> many1 (oneOf "0123456789abcdef")
  let lab' = pHex' 8 lab
  nodes <- many (try getNodeLabel) <* char '\n'
  return $ MULTIEQUAL ((node,lab'):nodes)
  where
    getNodeLabel = do
      node <- string " , " *> pVarNode
      lab <- string " , " *> many1 (oneOf "0123456789abcdef")
      let lab' = pHex' 8 lab
      return (node,lab')

pInstr3 :: GenParser Char st POp
pInstr3 = do
  instr <- choice $ map (\(x,y) -> try $ string x *> return y)
                                              [("LOAD",LOAD),("INT_SUB",INT_SUB),("INT_ADD",INT_ADD)
                                              ,("INT_AND",INT_AND),("INT_SLESSEQUAL",INT_SLESSEQUAL),("INT_SLESS",INT_SLESS)
                                              ,("INT_EQUAL",INT_EQUAL),("INT_LESSEQUAL",INT_LESSEQUAL),("INT_LESS",INT_LESS)
                                              ,("INT_SBORROW",INT_SBORROW),("INT_NOTEQUAL",INT_NOTEQUAL)
                                              ,("BOOL_OR",BOOL_OR),("INT_MULT",INT_MULT)
                                              ,("INT_SCARRY",INT_SCARRY),("INT_CARRY",INT_CARRY)
                                              ,("INDIRECT",INDIRECT),("SUBPIECE",SUBPIECE)
                                              ,("PIECE",PIECE),("INT_OR",INT_OR)
                                              ,("INT_SREM",INT_SREM),("INT_SDIV",INT_SDIV)
                                              ,("INT_SRIGHT",INT_SRIGHT),("INT_RIGHT",INT_RIGHT)
                                              ,("FLOAT_NOTEQUAL",FLOAT_NOTEQUAL),("FLOAT_EQUAL",FLOAT_EQUAL)
                                              ,("FLOAT_LESSEQUAL",FLOAT_LESSEQUAL),("FLOAT_LESS",FLOAT_LESS),("BOOL_AND",BOOL_AND)
                                              ,("INT_DIV",INT_DIV),("FLOAT_MULT",FLOAT_MULT)
                                              ,("FLOAT_ADD",FLOAT_ADD),("FLOAT_DIV",FLOAT_DIV)
                                              ,("FLOAT_SUB",FLOAT_SUB),("INT_LEFT",INT_LEFT)
                                              ,("INT_REM",INT_REM),("INT_XOR",INT_XOR)
                                              ,("BOOL_XOR",BOOL_XOR),("PTRSUB",PTRSUB)]
  node1 <- space *> pVarNode <* string " , "
  node2 <- pVarNode <* char '\n'
  return $ instr node1 node2

------------------------------------------------------------
-- VarNode parsers -----------------------------------------
------------------------------------------------------------

pVarNode ::GenParser Char st VarNode
pVarNode = choice $ map try [pReg,pMem,pVal,pStack,pUnique,pVar]

pReg :: GenParser Char st VarNode
pReg = do
  -- name <- string "(register, " *> many1 (oneOf "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890") <* string ", "
  name <- string "(register, 0x" *> many1 (oneOf "0123456789abcdef") <* string ", "
  size <- read <$> many1 digit <* char ')'
  let name' = pHex' 8 name
  return $ Reg name' (intToSize size)

pMem :: GenParser Char st VarNode
pMem = do
  addr <- string "(ram, 0x" *> many1 (oneOf "0123456789abcdef") <* string ", "
  size <- read <$> many1 digit <* char ')'
  let addr' = pHex' 8 addr
  return $ Ram addr' (intToSize size)

pVal :: GenParser Char st VarNode
pVal = do
  val <- string "(const, 0x" *> many1 (oneOf "0123456789abcdef") <* string ", "
  size <- read <$> many1 digit <* char ')'
  let val' = pHex' size val
  return (Const val' (intToSize size))

pStack :: GenParser Char st VarNode
pStack = do
  addr <- string "(stack, 0x" *> many1 (oneOf "ABCDEF1234567890abcdef") <* string ", "
  size <- read <$> many1 digit <* char ')'
  return (Variable ("stack_" ++ addr) (intToSize size))

pUnique :: GenParser Char st VarNode
pUnique = do
  addr <- (string "(unique, 0x" *> pHex) <* string ", "
  size <- read <$> many1 digit <* char ')'
  return (Variable ("u_" ++ show addr) (intToSize size))

pVar :: GenParser Char st VarNode
pVar = do
  addr <- (string "(VARIABLE, 0x" *> pHex) <* string ", "
  size <- read <$> many1 digit <* char ')'
  return (Variable ("var_" ++ show addr) (intToSize size))

------------------------------------------------------------
-- Hex parser -----------------------------------------
------------------------------------------------------------

pHex' :: Int -> String -> [Word8]
pHex' i val = let val' = replicate ((i*2)-length val) '0' ++ val in
    BS.unpack $ fromMaybe (error "illegal character in hex string") (decodeHex (T.pack val'))

pHex :: GenParser Char st Int
pHex = do
  val <- many1 (oneOf "0123456789abcdef")
  return $ parseHex val

hexChar :: Char -> Int
hexChar ch = fromMaybe (error $ "illegal char " ++ [ch]) $ elemIndex ch "0123456789abcdef"

parseHex :: Foldable t => t Char -> Int
parseHex = foldl' f 0 where f n c = 16*n + hexChar c
