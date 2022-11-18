{-|
Module      : PCode
Description : Ghidra P-Code language definitions
Copyright   : (c) Nico Naus, 2022
Maintainer  : niconaus@vt.edu
Stability   : experimental
This module defines the datatypes and translation of Ghidra P-Code
-}
module Types where

import qualified Data.Map as M
import Data.Word ( Word8 )
import qualified Data.ByteString as BS

-- Program in P-code

type PCode = M.Map Fname PBlocks

type PBlocks = M.Map Addr PBlock

-- Memory types

type State = (Mem,Regs,Vars)

type Mem = M.Map Addr Word8
-- Variables "return" and "last" are reserved and should not be used in PCode
type Vars = M.Map String [Word8]
type Regs = M.Map Addr Word8

-- Block address
type Addr = [Word8]

type Fname = [Word8] -- functions are identified by the starting address, since that is how they are called

type PBlock = [PInstr]

data PInstr = STORE VarNode VarNode VarNode | BRANCH VarNode
            | CBRANCH VarNode VarNode VarNode
            | BRANCHIND VarNode
            | RETURN VarNode (Maybe VarNode)
            | Do PCall | PCAss VarNode PCall | PAss VarNode POp deriving Show

data PCall = CALL VarNode [VarNode]
           | CALLIND VarNode [VarNode]
           | CALLOTHER VarNode [VarNode]
           -- EXTCALL is an artifical instruction, to encode which external function is called from this point
           | EXTCALL String deriving Show

data POp = COPY VarNode
         | LOAD VarNode VarNode
         | PIECE VarNode VarNode
         | SUBPIECE VarNode VarNode
         | POPCOUNT VarNode
         -- INTEGER OPERATIONS
         | INT_EQUAL VarNode VarNode
         | INT_NOTEQUAL VarNode VarNode
         | INT_LESS VarNode VarNode
         | INT_SLESS VarNode VarNode
         | INT_LESSEQUAL VarNode VarNode
         | INT_SLESSEQUAL VarNode VarNode
         | INT_ZEXT VarNode
         | INT_SEXT VarNode
         | INT_ADD VarNode VarNode
         | INT_SUB VarNode VarNode
         | INT_CARRY VarNode VarNode
         | INT_SCARRY VarNode VarNode
         | INT_SBORROW VarNode VarNode
         | INT_2COMP VarNode
         | INT_NEGATE VarNode
         | INT_XOR VarNode VarNode
         | INT_AND VarNode VarNode
         | INT_OR VarNode VarNode
         | INT_LEFT VarNode VarNode
         | INT_RIGHT VarNode VarNode
         | INT_SRIGHT VarNode VarNode
         | INT_MULT VarNode VarNode
         | INT_DIV VarNode VarNode
         | INT_REM VarNode VarNode
         | INT_SDIV VarNode VarNode
         | INT_SREM VarNode VarNode
         -- BOOLEAN OPERATIONS
         | BOOL_NEGATE VarNode
         | BOOL_XOR VarNode VarNode
         | BOOL_AND VarNode VarNode
         | BOOL_OR VarNode VarNode
         -- FLOATING POINT NUMBER OPERATIONS
         | FLOAT_EQUAL VarNode VarNode
         | FLOAT_NOTEQUAL VarNode VarNode
         | FLOAT_LESS VarNode VarNode
         | FLOAT_LESSEQUAL VarNode VarNode
         | FLOAT_ADD VarNode VarNode
         | FLOAT_SUB VarNode VarNode
         | FLOAT_MULT VarNode VarNode
         | FLOAT_DIV VarNode VarNode
         | FLOAT_NEG VarNode
         | FLOAT_ABS VarNode
         | FLOAT_SQRT VarNode
         | FLOAT_CEIL VarNode
         | FLOAT_FLOOR VarNode
         | FLOAT_ROUND VarNode
         | FLOAT_NAN VarNode
         | INT2FLOAT VarNode
         | FLOAT2FLOAT VarNode
         -- OTHER OPERATIONS
         | TRUNC VarNode
         -- UNDOCUMENTED INSTRUCTIONS
         -- | CALLOTHER VarNode [VarNode]-- I have no idea what this instruction does...
         -- ADDITIONAL INSTRUCTIONS
         | MULTIEQUAL [(VarNode,Addr)]
         | INDIRECT VarNode VarNode
         | PTRADD VarNode VarNode VarNode
         | PTRSUB VarNode VarNode
         | CAST VarNode deriving Show

data VarNode = Reg Addr Size
             | Ram Addr Size
             | Variable String Size
             | Const [Word8] Size deriving Show  -- String is hex representation

type Size = Word8

-- COMMON OPERATIONS ON PCODE TYPES

vnSize :: VarNode -> Size
vnSize (Ram _ s) = s
vnSize (Reg _ s) = s
vnSize (Const _ s) = s
vnSize (Variable _ s) = s

sizeToInt :: Size -> Int
sizeToInt = fromEnum

intToSize :: Int -> Size
intToSize = toEnum

-- REGISTER MAPPING
-- this mapping is established by experimental results
showReg :: Addr -> Size -> String
showReg [0,0,0,0,0,0,0,0] 8 = "RAX"
showReg [0,0,0,0,0,0,0,0] 4 = "EAX"
showReg [0,0,0,0,0,0,0,0] 2 = "AX"
showReg [0,0,0,0,0,0,0,0] 1 = "AL"
showReg [0,0,0,0,0,0,0,1] 1 = "AH"
showReg [0,0,0,0,0,0,0,8] 8 = "RCX"
showReg [0,0,0,0,0,0,0,8] 4 = "ECX"
showReg [0,0,0,0,0,0,0,8] 2 = "CX"
showReg [0,0,0,0,0,0,0,8] 1 = "BL"
showReg [0,0,0,0,0,0,0,9] 1 = "BH"
showReg [0,0,0,0,0,0,0,16] 8 = "RDX"
showReg [0,0,0,0,0,0,0,16] 4 = "EDX"
showReg [0,0,0,0,0,0,0,24] 8 = "RBX"
showReg [0,0,0,0,0,0,0,32] 8 = "RSP"
showReg [0,0,0,0,0,0,0,40] 8 = "RBP"
showReg [0,0,0,0,0,0,0,40] 4 = "EBP"
showReg [0,0,0,0,0,0,0,48] 8 = "RSI"
showReg [0,0,0,0,0,0,0,48] 4 = "ESI"
showReg [0,0,0,0,0,0,0,56] 8 = "RDI"
showReg [0,0,0,0,0,0,0,56] 4 = "EDI"

showReg [0,0,0,0,0,0,0,128] 8 = "R8"
showReg [0,0,0,0,0,0,0,136] 8 = "R9"
showReg [0,0,0,0,0,0,0,144] 8 = "R10"
-- showReg 152 8 = "R11"
-- showReg 160 8 = "R12"
-- showReg 168 8 = "R13"
-- showReg 176 8 = "R14"
-- showReg 176 4 = "R14D"
-- showReg 184 8 = "R15"
-- showReg 184 4 = "R15D"
--
-- showReg 512 1 = "CF"
-- showReg 514 1 = "PF"
showReg [0,0,0,0,0,0,2,6] 1 = "AF"
showReg [0,0,0,0,0,0,2,8] 1 = "ZF"
showReg [0,0,0,0,0,0,2,9] 1 = "SF"
showReg [0,0,0,0,0,0,2,10] 1 = "TF"
showReg [0,0,0,0,0,0,2,11] 1 = "IF"
showReg [0,0,0,0,0,0,2,12] 1 = "DF"
showReg [0,0,0,0,0,0,2,13] 1 = "OF"
--
-- showReg 1200 8 = "XMM0_Qa"

showReg a s = "UnmatchedReg " ++ show a ++ ":" ++ show s


-- PRETTY PRINTER for programs

prettyPF :: PCode -> String
prettyPF funs = concatMap (\(fl,blocks) -> "Function " ++ show fl ++ "\n" ++ prettyPBs blocks) (M.toList funs)

prettyPBs :: PBlocks -> String
prettyPBs blocks = concatMap (\(l,block) -> "   " ++ show l ++ "\n" ++ prettyPB block) (M.toList blocks)

prettyPB :: PBlock -> String
prettyPB [] = ""
prettyPB (x:xs) = "      " ++ show x ++ "\n" ++ prettyPB xs
