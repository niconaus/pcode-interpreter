{-|
Module      : PCode.Interpreter
Description : PCode interpreter
Copyright   : (c) Nico Naus, 2022
Maintainer  : niconaus@vt.edu
Stability   : experimental
This module defines a simple interpreter for Ghidra P-Code
-}
module PCode.Interpreter where

import qualified Data.Map as M
import PCode.Types
import PCode.Parser ( pFile )
import qualified Text.ParserCombinators.Parsec as P
import Data.Word ( Word8, Word16, Word32, Word64 )
import Data.Binary.IEEE754
    ( doubleToWord, floatToWord, wordToDouble, wordToFloat )
import Data.ByteString.Builder ()
import qualified Data.ByteString.Lazy as BS
import Data.Binary.Get
import qualified Text.Hex as Hex
import qualified Data.Text as Text
import Data.Bits
    ( Bits(shiftR, popCount, complement, (.&.), (.|.), shift, xor,
           shiftL) )
import GHC.Float
    ( double2Float,
      float2Double,
      integerLogBase,
      negateDouble,
      negateFloat )
import Data.Maybe (fromMaybe)
import WordString

---------------------
--- Register definitions
---------------------

retAddr, retVal, arg0, arg1, arg2, arg3, arg4, arg5 :: Addr
retAddr = [0,0,0,0,0,0,3,231]
retVal  = [0,0,0,0,0,0,3,120]
arg0 = [0,0,0,0,0,0,0,56]
arg1 = [0,0,0,0,0,0,0,48]
arg2 = [0,0,0,0,0,0,0,16]
arg3 = [0,0,0,0,0,0,0,8]
arg4 = [0,0,0,0,0,0,0,128]
arg5 = [0,0,0,0,0,0,0,136]

---------------------
--- EVALUATION FUNCTIONS
---------------------
-- This function takes a PCode program, together with an entry point, and returns a state
run :: PCode -> State -> Fname -> Addr -> State
run prog s f a = case M.lookup a blocks of
    Nothing -> error "block not found"
    Just b -> evalB blocks' a b s
  where blocks = fromMaybe (error $ "function not found: " ++ show f) (M.lookup f prog)
        blocks' = M.unions $ map snd $ M.toList prog

-- a is the current block address, so next can be calculated
evalB :: PBlocks -> Addr -> PBlock -> State -> State
--- no terminator seen, advance to next block
evalB p a [] (mem,r,var) = evalB p next (getBlock p next) s
  where next = getNext p a
        s    = (mem, setReg r retAddr a,var)
--- terminator instructions
evalB p a [BRANCH vn] (m,r,v) = evalB p next (getBlock p next) s
  where next = getAddress vn
        s    = (m, setReg r retAddr a,v)
   -- NOTE: there is an error in CBRANCH on Ghidra's side. We assume that this is fixed by dumping script
evalB p a [BRANCHIND vn] state = evalB p a [BRANCH (Ram (getVN state vn) 8)] state
evalB p a [CBRANCH vn1 vn2 vn3] (m,r,v) | toBool (decodeWord8 $ getVN (m,r,v) vn3) = let next = getAddress vn1 in evalB p next (getBlock p next) s
                                        | otherwise = let next = getAddress vn2 in evalB p next (getBlock p next) s
  where s = (m, setReg r retAddr a,v)
evalB _ a [RETURN _ Nothing]   (m,r,v) = (m,r,v)
evalB _ a [RETURN _ (Just vn)] (m,r,v) = (m,setReg r retVal (getVN (m,r,v) vn),v)
-- --- sequential evaluation
evalB p a (x:xs) s = evalB p a xs (evalI p a x s)

evalI :: PBlocks -> Addr -> PInstr -> State -> State
evalI _ a (STORE _ output input)      (mem,r,vars) = (writeMem mem (getVN (mem,r,vars) input)( encodeWord64 $ getVN64 (mem,r,vars) output),r,vars)  -- again, assuming 64 bits
evalI p _ (Do call)                   state        = fst $ evalS p call 8 state
evalI p _ (PCAss (Reg n s) call)      state        = (\((m',r',v'),res) -> (m',setReg r' n res,v')) (evalS p call s state)
evalI p _ (PCAss (Ram a s) call)      state        = (\((m',r',v'),res) -> (writeMem m' res a,r',v')) (evalS p call s state)
evalI p _ (PCAss (Variable n s) call) state        = (\((m',r',v'),res) -> (m',r',setVar v' n res)) (evalS p call s state)
evalI _ a (PAss (Reg n s) i)          (mem,reg,vars) = (\e -> if sizeToInt s == length e then (mem,setReg reg n e,vars) else error "error") (evalO i s (mem,reg,vars))
evalI _ a ins@(PAss (Variable n s) i) (mem,reg,vars) = (\e -> if sizeToInt s == length e then (mem,reg,setVar vars n e) else error $ "error" ++ show ins ++ " " ++ show e) (evalO i s (mem,reg,vars))
evalI _ a (PAss (Ram r s) i)          (mem,reg,vars) = (\e -> if sizeToInt s == length e then (writeMem mem e r, reg,vars) else error "error") (evalO i s (mem,reg,vars))
evalI _ _ (PAss (Const _ _) _)  _ = error "assignment into a constant. There is something wrong with your P-Code"
evalI _ _ (PCAss (Const _ _) _) _ = error "assignment into a constant. There is something wrong with your P-Code"
evalI _ _ (BRANCH _)            _ = error "BRANCH instruction should be handled at evalB level"
evalI _ _ CBRANCH {}            _ = error "CBRANCH instruction should be handled at evalB level"
evalI _ _ (BRANCHIND _)         _ = error "BRANCHIND instruction should be handled at evalB level"
evalI _ _ (RETURN _ _)          _ = error "RETURN instruction should be handled at evalB level"

evalS :: PBlocks -> PCall -> Size -> State -> (State,[Word8])
evalS p (CALL vn args) s (m,r,v) = assemble res
  where reg = foldr (\(vn',a') r' -> setReg r' a' (getVN (m,r,v) vn')) r (zip args [arg0,arg1,arg2,arg3,arg4,arg5])
        dest = getAddress vn
        res = evalB p dest (getBlock p dest) (m,resetReg reg retAddr 8,M.empty)
        restoreRegisters cr = foldr (\a r' -> setReg r' a (getReg r a 8)) cr [arg0,arg1,arg2,arg3,arg4,arg5,retAddr] --TODO: what about ret vale?
        assemble = \(m',r',_) -> ((m',restoreRegisters r',v), getReg r' retVal s)
evalS p (CALLIND vn args) s state = evalS p (CALL (Ram (getVN state vn) 8) args) s state
evalS _ (EXTCALL _) _ _ = error "External calls not supported for now"
evalS _ (CALLOTHER _ _) _ _ = error "External calls not supported for now"

evalO :: POp -> Size -> State -> [Word8]
evalO (COPY vn)                 i  s = if i == vnSize vn then getVN s vn else error "error!"
evalO (LOAD _ vn)        s (mem,reg,vars) = readMem mem (getVN (mem,reg,vars) vn) s
evalO (PIECE vn1 vn2)           _  s = getVN s vn1 ++ getVN s vn2
evalO (SUBPIECE vn1 vn2)        _  s = case vnSize vn2 of
        8 -> drop (sizeToInt (vnSize vn1) - 8 - l) (take l (getVN s vn1)) where l = fromEnum $ getVN64 s vn2
        _ -> error "case for this size not defined"
evalO (POPCOUNT vn)             n s = zeroExtend n [toEnum $ sum (map popCount (getVN s vn))]
-- INTEGER OPERATIONS
evalO (INT_EQUAL vn1 vn2)       1 s | vnSize vn1 == 8 = if getVN64 s vn1 == getVN64 s vn2 then [trueW] else [falseW]
                                    | vnSize vn1 == 4 = if getVN32 s vn1 == getVN32 s vn2 then [trueW] else [falseW]
                                    | vnSize vn1 == 2 = if getVN16 s vn1 == getVN16 s vn2 then [trueW] else [falseW]
                                    | vnSize vn1 == 1 = if getVN8  s vn1 == getVN8  s vn2 then [trueW] else [falseW]
evalO (INT_EQUAL _ _ )          _  _ = error "Boolean operation requested for a size larger than 1"
evalO (INT_NOTEQUAL vn1 vn2)    1 s | vnSize vn1 == 8 = if getVN64 s vn1 /= getVN64 s vn2 then [trueW] else [falseW]
                                    | vnSize vn1 == 4 = if getVN32 s vn1 /= getVN32 s vn2 then [trueW] else [falseW]
                                    | vnSize vn1 == 2 = if getVN16 s vn1 /= getVN16 s vn2 then [trueW] else [falseW]
                                    | vnSize vn1 == 1 = if getVN8 s vn1  /= getVN8  s vn2 then [trueW] else [falseW]
evalO (INT_NOTEQUAL _ _ )       _  _ = error "Boolean operation requested for a size larger than 1"
evalO (INT_LESS vn1 vn2)        1 s | vnSize vn1 == 8 = if getVN64 s vn1 < getVN64 s vn2 then [trueW] else [falseW]
                                    | vnSize vn1 == 4 = if getVN32 s vn1 < getVN32 s vn2 then [trueW] else [falseW]
                                    | vnSize vn1 == 2 = if getVN16 s vn1 < getVN16 s vn2 then [trueW] else [falseW]
                                    | vnSize vn1 == 1 = if getVN8  s vn1 < getVN8  s vn2 then [trueW] else [falseW]
evalO (INT_LESS _ _ )           _ _ = error "Boolean operation requested for a size larger than 1"
evalO (INT_SLESS vn1 vn2)       1 s = if bs2i (getVN s vn1) < bs2i (getVN s vn2) then [trueW] else [falseW]
evalO (INT_SLESS _ _ )          _ _ = error "Boolean operation requested for a size larger than 1"
evalO (INT_LESSEQUAL vn1 vn2)   1 s = if getVN64 s vn1 <= getVN64 s vn2 then [trueW] else [falseW]
evalO (INT_LESSEQUAL _ _ )      _ _ = error "Boolean operation requested for a size larger than 1"
evalO (INT_SLESSEQUAL vn1 vn2)  1 s = if bs2i (getVN s vn1) <= bs2i (getVN s vn2) then [trueW] else [falseW]
evalO (INT_SLESSEQUAL _ _ )     _ _ = error "Boolean operation requested for a size larger than 1"
evalO (INT_ZEXT vn)             i s = zeroExtend i (getVN s vn)
evalO (INT_SEXT vn)             i s = signExtend i (getVN s vn)
evalO (INT_ADD vn1 vn2)         1 s = operate8  (getVN s vn1) (getVN s vn2) (+)
evalO (INT_ADD vn1 vn2)         2 s = operate16 (getVN s vn1) (getVN s vn2) (+)
evalO (INT_ADD vn1 vn2)         4 s = operate32 (getVN s vn1) (getVN s vn2) (+)
evalO (INT_ADD vn1 vn2)         8 s = operate64 (getVN s vn1) (getVN s vn2) (+)
evalO (INT_ADD _ _)             _ _ = error "Cannot perform addition on irregular shaped bytestring"
evalO (INT_SUB vn1 vn2)         1 s = operate8  (getVN s vn1) (getVN s vn2) (-)
evalO (INT_SUB vn1 vn2)         2 s = operate16 (getVN s vn1) (getVN s vn2) (-)
evalO (INT_SUB vn1 vn2)         4 s = operate32 (getVN s vn1) (getVN s vn2) (-)
evalO (INT_SUB vn1 vn2)         8 s = operate64 (getVN s vn1) (getVN s vn2) (-)
evalO (INT_SUB _ _)             _ _ = error "Cannot perform subtraction on irregular shaped bytestring"
evalO (INT_CARRY vn1 vn2)       1 s | vnSize vn1 == 8 = if (a + b) < max a b then [trueW] else [falseW]
                                      where a = getVN64 s vn1
                                            b = getVN64 s vn2
evalO (INT_CARRY _ _ )          _ _ = error "Boolean operation requested for a size larger than 1"
evalO (INT_SCARRY _ _)          _ _ = undefined
evalO (INT_SBORROW _ _)         _ _ = undefined
evalO (INT_2COMP vn)            1 s = encodeWord8  $ complement (getVN8 s vn)  + 1
evalO (INT_2COMP vn)            2 s = encodeWord16 $ complement (getVN16 s vn) + 1
evalO (INT_2COMP vn)            4 s = encodeWord32 $ complement (getVN32 s vn) + 1
evalO (INT_2COMP vn)            8 s = encodeWord64 $ complement (getVN64 s vn) + 1
evalO (INT_2COMP _)             _ _ = error "Cannot perform complement on irregular shaped bytestring"
evalO (INT_NEGATE vn)           1 s = encodeWord8  $ complement (getVN8 s vn)
evalO (INT_NEGATE vn)           2 s = encodeWord16 $ complement (getVN16 s vn)
evalO (INT_NEGATE vn)           4 s = encodeWord32 $ complement (getVN32 s vn)
evalO (INT_NEGATE vn)           8 s = encodeWord64 $ complement (getVN64 s vn)
evalO (INT_NEGATE _)             _ _ = error "Cannot perform negation on irregular shaped bytestring"
evalO (INT_XOR vn1 vn2)         1 s = operate8  (getVN s vn1) (getVN s vn2) xor
evalO (INT_XOR vn1 vn2)         2 s = operate16 (getVN s vn1) (getVN s vn2) xor
evalO (INT_XOR vn1 vn2)         4 s = operate32 (getVN s vn1) (getVN s vn2) xor
evalO (INT_XOR vn1 vn2)         8 s = operate64 (getVN s vn1) (getVN s vn2) xor
evalO (INT_XOR _ _)             _ _ = error "Cannot perform xor on irregular shaped bytestring"
evalO (INT_AND vn1 vn2)         1 s = operate8  (getVN s vn1) (getVN s vn2) (.&.)
evalO (INT_AND vn1 vn2)         2 s = operate16 (getVN s vn1) (getVN s vn2) (.&.)
evalO (INT_AND vn1 vn2)         4 s = operate32 (getVN s vn1) (getVN s vn2) (.&.)
evalO (INT_AND vn1 vn2)         8 s = operate64 (getVN s vn1) (getVN s vn2) (.&.)
evalO (INT_AND _ _)             _ _ = error "Cannot perform AND on irregular shaped bytestring"
evalO (INT_OR vn1 vn2)          1 s = operate8  (getVN s vn1) (getVN s vn2) (.|.)
evalO (INT_OR vn1 vn2)          2 s = operate16 (getVN s vn1) (getVN s vn2) (.|.)
evalO (INT_OR vn1 vn2)          4 s = operate32 (getVN s vn1) (getVN s vn2) (.|.)
evalO (INT_OR vn1 vn2)          8 s = operate64 (getVN s vn1) (getVN s vn2) (.|.)
evalO (INT_OR _ _)              _ _ = error "Cannot perform or on irregular shaped bytestring"
evalO (INT_LEFT vn1 vn2)        1 s = encodeWord8  $ shift (decodeWord8  (getVN s vn1)) (fromEnum $ getVN8  s vn2)
evalO (INT_LEFT vn1 vn2)        2 s = encodeWord16 $ shift (decodeWord16 (getVN s vn1)) (fromEnum $ getVN16 s vn2)
evalO (INT_LEFT vn1 vn2)        4 s = encodeWord32 $ shift (decodeWord32 (getVN s vn1)) (fromEnum $ getVN32 s vn2)
evalO (INT_LEFT vn1 vn2)        8 s = encodeWord64 $ shift (decodeWord64 (getVN s vn1)) (fromEnum $ getVN64 s vn2)
evalO (INT_LEFT _ _)            _ _ = error "Cannot perform left shift on irregular shaped bytestring"
evalO (INT_RIGHT vn1 vn2)       1 s = encodeWord8  $ shiftR (decodeWord8  (getVN s vn1)) (fromEnum $ getVN8 s vn2)
evalO (INT_RIGHT vn1 vn2)       2 s = encodeWord16 $ shiftR (decodeWord16 (getVN s vn1)) (fromEnum $ getVN16 s vn2)
evalO (INT_RIGHT vn1 vn2)       4 s = encodeWord32 $ shiftR (decodeWord32 (getVN s vn1)) (fromEnum $ getVN32 s vn2)
evalO (INT_RIGHT vn1 vn2)       8 s = encodeWord64 $ shiftR (decodeWord64 (getVN s vn1)) (fromEnum $ getVN64 s vn2)
evalO (INT_RIGHT _ _)           _ _ = error "Cannot perform right shift on irregular shaped bytestring"
evalO (INT_SRIGHT vn1 vn2)      1 s = BS.unpack $ i2bs $ shiftR (bs2i (getVN s vn1)) (fromEnum $ getVN8 s vn2)
evalO (INT_SRIGHT vn1 vn2)      2 s = BS.unpack $ i2bs $ shiftR (bs2i (getVN s vn1)) (fromEnum $ getVN16 s vn2)
evalO (INT_SRIGHT vn1 vn2)      4 s = BS.unpack $ i2bs $ shiftR (bs2i (getVN s vn1)) (fromEnum $ getVN32 s vn2)
evalO (INT_SRIGHT vn1 vn2)      8 s = BS.unpack $ i2bs $ shiftR (bs2i (getVN s vn1)) (fromEnum $ getVN64 s vn2)
evalO (INT_SRIGHT _ _)          _ _ = error "Cannot perform right shift on irregular shaped bytestring"
evalO (INT_MULT vn1 vn2)        1 s = operate8  (getVN s vn1) (getVN s vn2) (*)
evalO (INT_MULT vn1 vn2)        2 s = operate16 (getVN s vn1) (getVN s vn2) (*)
evalO (INT_MULT vn1 vn2)        4 s = operate32 (getVN s vn1) (getVN s vn2) (*)
evalO (INT_MULT vn1 vn2)        8 s = operate64 (getVN s vn1) (getVN s vn2) (*)
evalO (INT_MULT _ _)            _ _ = error "Cannot perform multiplication on irregular shaped bytestring"
evalO (INT_DIV vn1 vn2)         1 s = operate8  (getVN s vn1) (getVN s vn2) div
evalO (INT_DIV vn1 vn2)         2 s = operate16 (getVN s vn1) (getVN s vn2) div
evalO (INT_DIV vn1 vn2)         4 s = operate32 (getVN s vn1) (getVN s vn2) div
evalO (INT_DIV vn1 vn2)         8 s = operate64 (getVN s vn1) (getVN s vn2) div
evalO (INT_DIV _ _)             _ _ = error "Cannot perform division on irregular shaped bytestring"
evalO (INT_REM vn1 vn2)         1 s = operate8  (getVN s vn1) (getVN s vn2) rem
evalO (INT_REM vn1 vn2)         2 s = operate16 (getVN s vn1) (getVN s vn2) rem
evalO (INT_REM vn1 vn2)         4 s = operate32 (getVN s vn1) (getVN s vn2) rem
evalO (INT_REM vn1 vn2)         8 s = operate64 (getVN s vn1) (getVN s vn2) rem
evalO (INT_REM _ _)             _ _ = error "Cannot perform rem on irregular shaped bytestring"
evalO (INT_SDIV vn1 vn2)        i  s = signExtend i $ BS.unpack $ i2bs (div (bs2i $ getVN s vn1) (bs2i $ getVN s vn2))
evalO (INT_SREM vn1 vn2)        i  s = signExtend i $ BS.unpack $ i2bs $ rem (bs2i $ getVN s vn1) (bs2i $ getVN s vn2)
-- BOOLEAN OPERATIONS
evalO (BOOL_NEGATE vn)          1 s = encodeWord8 $ fromBool (not $ toBool (decodeWord8 $ getVN s vn))
evalO (BOOL_NEGATE _)           _ _ = error "Boolean operation requested for a size larger than 1"
evalO (BOOL_XOR vn1 vn2)        1 s = encodeWord8 (fromBool (xor (toBool (decodeWord8 (getVN s vn1))) (toBool (decodeWord8 $ getVN s vn2))))
evalO(BOOL_XOR _ _)             _ _ = error "Boolean operation requested for a size larger than 1"
evalO (BOOL_AND vn1 vn2)        1 s = encodeWord8 (fromBool (toBool (decodeWord8 (getVN s vn1)) && toBool (decodeWord8 $ getVN s vn2)))
evalO(BOOL_AND _ _)             _ _ = error "Boolean operation requested for a size larger than 1"
evalO (BOOL_OR vn1 vn2)         1 s = encodeWord8 (fromBool (toBool (decodeWord8 (getVN s vn1)) || toBool (decodeWord8 $ getVN s vn2)))
evalO(BOOL_OR _ _)              _ _ = error "Boolean operation requested for a size larger than 1"
-- FLOATING POINT NUMBER OPERATIONS
evalO (FLOAT_EQUAL vn1 vn2)     1 s | vnSize vn1 == 8 = if wordToDouble (getVN64 s vn1) == wordToDouble (getVN64 s vn2) then [trueW] else [falseW]
                                    | vnSize vn1 == 4 = if wordToFloat (getVN32 s vn1) == wordToFloat (getVN32 s vn2) then [trueW] else [falseW]
                                    | otherwise = error "I don't think this is a float"
evalO(FLOAT_EQUAL _ _)          _ _ = error "Boolean operation requested for a size larger than 1"
evalO (FLOAT_NOTEQUAL vn1 vn2)  1 s | vnSize vn1 == 8 = if wordToDouble (getVN64 s vn1) /= wordToDouble (getVN64 s vn2) then [trueW] else [falseW]
                                    | vnSize vn1 == 4 = if wordToFloat (getVN32 s vn1) /= wordToFloat (getVN32 s vn2) then [trueW] else [falseW]
                                    | otherwise = error "I don't think this is a float"
evalO(FLOAT_NOTEQUAL _ _)       _ _ = error "Boolean operation requested for a size larger than 1"
evalO (FLOAT_LESS vn1 vn2)      1 s | vnSize vn1 == 8 = if wordToDouble (getVN64 s vn1) < wordToDouble (getVN64 s vn2) then [trueW] else [falseW]
                                    | vnSize vn1 == 4 = if wordToFloat (getVN32 s vn1) < wordToFloat (getVN32 s vn2) then [trueW] else [falseW]
                                    | otherwise = error "I don't think this is a float"
evalO(FLOAT_LESS _ _)           _ _ = error "Boolean operation requested for a size larger than 1"
evalO (FLOAT_LESSEQUAL vn1 vn2) 1 s | vnSize vn1 == 8 = if wordToDouble (getVN64 s vn1) <= wordToDouble (getVN64 s vn2) then [trueW] else [falseW]
                                    | vnSize vn1 == 4 = if wordToFloat (getVN32 s vn1) <= wordToFloat (getVN32 s vn2) then [trueW] else [falseW]
                                    | otherwise = error "I don't think this is a float"
evalO(FLOAT_LESSEQUAL _ _)      _ _ = error "Boolean operation requested for a size larger than 1"
evalO (FLOAT_ADD vn1 vn2)       8 s = encodeWord64$ doubleToWord (wordToDouble (getVN64 s vn1) + wordToDouble (getVN64 s vn2))
evalO (FLOAT_ADD vn1 vn2)       4 s = encodeWord32$ floatToWord (wordToFloat (getVN32 s vn1) + wordToFloat (getVN32 s vn2))
evalO (FLOAT_ADD _ _)           _ _ = error "I don't think this is a float"
evalO (FLOAT_SUB vn1 vn2)       8 s = encodeWord64$ doubleToWord (wordToDouble (getVN64 s vn1) - wordToDouble (getVN64 s vn2))
evalO (FLOAT_SUB vn1 vn2)       4 s = encodeWord32$ floatToWord (wordToFloat (getVN32 s vn1) - wordToFloat (getVN32 s vn2))
evalO (FLOAT_SUB _ _)           _ _ = error "I don't think this is a float"
evalO (FLOAT_MULT vn1 vn2)      8 s = encodeWord64 $ doubleToWord (wordToDouble (getVN64 s vn1) * wordToDouble (getVN64 s vn2))
evalO (FLOAT_MULT vn1 vn2)      4 s = encodeWord32 $ floatToWord (wordToFloat (getVN32 s vn1) * wordToFloat (getVN32 s vn2))
evalO (FLOAT_MULT _ _)          _ _ = error "I don't think this is a float"
evalO (FLOAT_DIV vn1 vn2)       8 s = encodeWord64$ doubleToWord (wordToDouble (getVN64 s vn1) / wordToDouble (getVN64 s vn2))
evalO (FLOAT_DIV vn1 vn2)       4 s = encodeWord32$ floatToWord (wordToFloat (getVN32 s vn1) / wordToFloat (getVN32 s vn2))
evalO (FLOAT_DIV _ _)           _ _ = error "I don't think this is a float"
evalO (FLOAT_NEG vn)            8 s = encodeWord64$ doubleToWord (negateDouble (wordToDouble $ getVN64 s vn))
evalO (FLOAT_NEG vn)            4 s = encodeWord32 $ floatToWord (negateFloat  (wordToFloat  $ getVN32 s vn))
evalO (FLOAT_NEG _)             _ _ = error "I don't think this is a float"
evalO (FLOAT_ABS vn)            8 s = encodeWord64 $ doubleToWord (abs (wordToDouble $ getVN64 s vn))
evalO (FLOAT_ABS vn)            4 s = encodeWord32 $ floatToWord  (abs (wordToFloat  $ getVN32 s vn))
evalO (FLOAT_ABS _)             _ _ = error "I don't think this is a float"
evalO (FLOAT_SQRT vn)           8 s = encodeWord64 $ doubleToWord (sqrt (wordToDouble $ getVN64 s vn))
evalO (FLOAT_SQRT vn)           4 s = encodeWord32 $ floatToWord  (sqrt (wordToFloat  $ getVN32 s vn))
evalO (FLOAT_SQRT _)            _ _ = error "I don't think this is a float"
evalO (FLOAT_CEIL vn)           8 s = encodeWord64 (ceiling (wordToDouble $ getVN64 s vn))
evalO (FLOAT_CEIL vn)           4 s = encodeWord32 (ceiling (wordToFloat  $ getVN32 s vn))
evalO (FLOAT_CEIL _ )           _ _ = error "I don't think this is a float"
evalO (FLOAT_FLOOR vn)          8 s = encodeWord64 (floor (wordToDouble $ getVN64 s vn))
evalO (FLOAT_FLOOR vn)          4 s = encodeWord32 (floor (wordToFloat  $ getVN32 s vn))
evalO (FLOAT_FLOOR _)           _ _ = error "I don't think this is a float"
evalO (FLOAT_ROUND vn)          8 s = encodeWord64 (round (wordToDouble $ getVN64 s vn))
evalO (FLOAT_ROUND vn)          4 s = encodeWord32 (round (wordToFloat  $ getVN32 s vn))
evalO (FLOAT_ROUND _)           _ _ = error "I don't think this is a float"
evalO (FLOAT_NAN vn)            1 s | vnSize vn == 8 = encodeWord8 $ fromBool (isNaN (wordToDouble $ getVN64 s vn))
                                    | vnSize vn == 4 = encodeWord8 $ fromBool (isNaN (wordToFloat  $ getVN32 s vn))
                                    | otherwise = error "I don't think this is a float"
evalO (FLOAT_NAN _ )            _ _ = error "Boolean operation requested for a size larger than 1"
evalO (INT2FLOAT vn)            8 s = encodeWord64 $ doubleToWord $ toEnum $ fromEnum $ getVN64 s vn
evalO (INT2FLOAT vn)            4 s = encodeWord32 $ floatToWord $ toEnum $ fromEnum $ getVN32 s vn
evalO (INT2FLOAT _ )            _ _ = error "Destination size too small"
evalO (FLOAT2FLOAT vn)          i s = case (vnSize vn,i) of
  (4,8) -> encodeWord64$ doubleToWord (float2Double (wordToFloat $ getVN32 s vn))
  (8,4) -> encodeWord32$ floatToWord (double2Float (wordToDouble $ getVN64 s vn))
  _     -> error "Float destination and input have to be of different sizes and should be either 4 or 8 bytes"
evalO (TRUNC vn)                8 s = encodeWord64 $ toEnum $ fromEnum (wordToDouble $ getVN64 s vn)
evalO (TRUNC vn)                4 s = encodeWord32 $ toEnum $ fromEnum (wordToFloat $ getVN32 s vn)
evalO (TRUNC _ )                _ _ = error "I don't think this is a float"
-- Special operations
evalO (INDIRECT vn1 _)          _ s = getVN s vn1 -- We need to do something special here; vn1 might be the value, it might not be
    -- NOTE: Often times, a varnode is not set in MULTIEQUAL, so we can discard that path if that is the case
evalO (MULTIEQUAL vns)    _ (m,r,v) = if not (null vns') then head vns' else error "no suitable varNode found in multiequal"
  where a = getVN (m,r,v) (Reg retAddr 8)
        vns' = [getVN (m,r,v) vn | (vn,a') <- vns, a'==a]
evalO (PTRSUB vn1 vn2)          i s = evalO (INT_ADD vn1 vn2) i s
evalO (PTRADD vn1 vn2 vn3)      i s = (\x -> evalO (INT_ADD vn1 (Const x i)) i s) (evalO (INT_MULT vn2 vn3) i s)
evalO (CAST vn)                 _ s = getVN s vn






---------------------
--- MEMORY FUNCTIONS
---------------------
getVN64 ::State -> VarNode -> Word64
getVN64 s v = if length (getVN s v) == 8 then  decodeWord64 $ getVN s v else error $ "Tried to make a Word64 of varnode " ++ show v

getVN32 ::State -> VarNode -> Word32
getVN32 s v = if length (getVN s v) == 4 then  decodeWord32 $ getVN s v else error $ "Tried to make a Word32 of varnode " ++ show v ++ ", which contains " ++ show (getVN s v) ++ ", and state contains: " ++ show s

getVN16 ::State -> VarNode -> Word16
getVN16 s v = if length (getVN s v) == 2 then  decodeWord16 $ getVN s v else error $ "Tried to make a Word16 of varnode " ++ show v ++ ", which contains " ++ show (getVN s v) ++ ", and state contains: " ++ show s

getVN8 ::State -> VarNode -> Word8
getVN8 s v = if length (getVN s v) == 1 then  decodeWord8 $ getVN s v else error $ "Tried to make a Word8 of varnode " ++ show v ++ ", which contains " ++ show (getVN s v) ++ ", and state contains: " ++ show s


getVN :: State -> VarNode -> [Word8]
getVN (mem,_,_)  (Ram a n)    = readMem mem a n
getVN (_,reg,_)  (Reg r s)    = getReg reg r s
getVN _          (Const i _)  = i
getVN (_,_,vars) (Variable n _) = getVar vars n

getAddress :: VarNode -> [Word8]
getAddress (Ram a _) = a
getAddress _ = error "unexpected address notation"

writeMem :: Mem -> [Word8] -> Addr -> Mem
writeMem mem x a = foldr (\(v,i) mem' -> M.insert (encodeWord64 (decodeWord64 a + decodeWord64 (zeroExtend 8 [i]))) v mem') mem (zip x [0..])

readMem :: Mem -> Addr -> Size -> [Word8]
readMem mem a n = reverse $ map (\i -> read (encodeWord64 (decodeWord64 a + decodeWord64 (zeroExtend 8 [i])))) [0..(n-1)]
    where read a1 = fromMaybe err (M.lookup a1 mem)
          err = error $ "memory location "++ show a ++ " not initialized" ++ show mem

setReg :: Regs -> Addr -> [Word8] -> Regs
setReg reg a x = foldr (\(v,i) reg' -> M.insert (encodeWord64 (decodeWord64 a + decodeWord64 (zeroExtend 8 [i]))) v reg') reg (zip (reverse x) [0..])

getReg :: Regs -> Addr -> Size -> [Word8]
getReg reg a n = reverse $ map (\i -> read (encodeWord64 (decodeWord64 a + decodeWord64 (zeroExtend 8 [i])))) [0..(n-1)]
  where read a1 = fromMaybe err (M.lookup a1 reg)
        err = error $ "register location "++ show a ++ " not initialized" ++ show reg ++ " of size " ++ show n

-- size in BYTES! So a size of 1 returns 8 bits


getVar :: Vars -> String -> [Word8]
getVar v s = case M.lookup s v of
  Nothing -> error $ "variable " ++ s ++ " undefined. Memory contains: " ++ show v
  Just a -> a

setVar :: Vars -> String -> [Word8] -> Vars
setVar v s w = M.insert s w v

resetReg :: Regs -> Addr -> Size -> Regs
resetReg reg a s = foldr (\i reg' -> M.delete (encodeWord64 (decodeWord64 a + decodeWord64 (zeroExtend 8 [i]))) reg') reg [0..(s-1)]


getNext :: PBlocks -> Addr -> Addr
getNext p a = nextA a (blockL p) []

blockL :: PBlocks -> [Addr]
blockL pcode = map fst $ M.toList pcode

-- we assume the address list to be sorted
nextA :: Addr -> [Addr] -> [Addr] -> Addr
nextA x [] xs = error $ "I was unable to find the next block, there is no such thing." ++ show x ++ " next not in " ++ show xs
nextA a (x:xs) i | x > a = x
                 | otherwise = nextA a xs (x:i)

-- REGISTER functions

restoreReg :: Regs -> Regs -> Regs
restoreReg old new = M.unions [newFresh,old1,old2,old3]
 where newFresh = resetReg (resetReg (resetReg new [0,0,0,0,0,0,0,8] 16) [0,0,0,0,0,0,0,48] 16) [0,0,0,0,0,0,0,128] 16
       old1 = setReg M.empty [0,0,0,0,0,0,0,8] (getReg old [0,0,0,0,0,0,0,8] 16)
       old2 = setReg M.empty [0,0,0,0,0,0,0,48] (getReg old [0,0,0,0,0,0,0,48] 16)
       old3 = setReg M.empty [0,0,0,0,0,0,0,128] (getReg old [0,0,0,0,0,0,0,128] 16)

emptyReg :: Regs
emptyReg = foldr (\(Reg i _) m -> setReg m i [0,0,0,0,0,0,0,0]) M.empty argRegs -- M.fromList [("RSP",BS.unpack $ encode (64 :: Word64)),("EDI",(signExtend 4 $ BS.unpack $ i2bs 55 ))]

argRegs :: [VarNode]
argRegs = [Reg arg0 8,Reg arg1 8
          ,Reg arg2 8,Reg arg3 8
          ,Reg arg4 8,Reg arg5 8]
---------------------
--- PCODE ACCESS FUNCTIONS
---------------------

getBlock :: PBlocks -> Addr -> PBlock
getBlock p a = case M.lookup a p of
  Nothing -> error $ "block " ++ show a ++ " not found in " ++ show p
  Just b -> b

---------------------
--- OPERATIONS
---------------------

trueW, falseW :: Word8
trueW = toEnum 1
falseW = toEnum 0

boolNegate :: Word8 -> Word8
boolNegate xs | xs == 0 = 1
              | otherwise = 0

---------------------
--- Helpers
---------------------

fromFloat :: Float -> Word32
fromFloat = floatToWord

--We use Big endian encoding... This is kinda arbitrary

operate8 :: [Word8] -> [Word8] -> (Word8 -> Word8 -> Word8) -> [Word8]
operate8 wx wy f = encodeWord8(f (decodeWord8 wx) (decodeWord8 wy))

operate16 :: [Word8] -> [Word8] -> (Word16 -> Word16 -> Word16) -> [Word8]
operate16 wx wy f = encodeWord16(f (decodeWord16 wx) (decodeWord16 wy))

operate32 :: [Word8] -> [Word8] -> (Word32 -> Word32 -> Word32) -> [Word8]
operate32 wx wy f = encodeWord32(f (decodeWord32 wx) (decodeWord32 wy))

operate64 :: [Word8] -> [Word8] -> (Word64 -> Word64 -> Word64) -> [Word8]
operate64 wx wy f = encodeWord64(f (decodeWord64 wx) (decodeWord64 wy))

floatOperate64 :: [Word8] -> [Word8] -> (Word64 -> Word64 -> Word64) -> [Word8]
floatOperate64 wx wy f = encodeWord64(f (decodeWord64 wx) (decodeWord64 wy))

fromHex :: String -> [Word8]
fromHex s = case (Hex.decodeHex . Text.pack) s of
  Nothing -> error $ "could not read hex string " ++ s
  Just w -> (BS.unpack . Hex.lazyByteString) w

--we assume 0 is false and everything else is true
toBool :: Word8 -> Bool
toBool = (/=) 0

fromBool :: Bool -> Word8
fromBool True = 1
fromBool False = 0

-- Two's complement conversion functions
bs2i :: [Word8] -> Integer
bs2i bs
   | sign = go b - 2 ^ (BS.length b * 8)
   | otherwise = go b
   where
      b = BS.pack bs
      go = BS.foldl' (\i b' -> (i `shiftL` 8) + fromIntegral b') 0
      sign = BS.index b 0 > 127

i2bs :: Integer -> BS.ByteString
i2bs x
   | x == 0 = BS.singleton 0
   | x < 0 = i2bs $ 2 ^ (8 * bytes) + x
   | otherwise = BS.reverse $ BS.unfoldr go x
   where
      bytes = (integerLogBase 2 (abs x) + 1) `quot` 8 + 1
      go i = if i == 0 then Nothing
                       else Just (fromIntegral i, i `shiftR` 8)
