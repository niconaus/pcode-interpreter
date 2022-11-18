{-|
Module      : PCode
Description : PCode file
Copyright   : (c) Nico Naus, 2022
Maintainer  : niconaus@vt.edu
Stability   : experimental
This module defines interfaces for interpreter and parser of P-Code
-}

module PCode where

import qualified Text.ParserCombinators.Parsec as P
import qualified Data.Map as M
import Parser ( pFile )
import Interpreter
import WordString ( decodeWord32, encodeWord64 )

main :: IO ()
main = do
    putStrLn "P-Code interpreter \nPlease input P-Code file"
    src <- getLine
    let src' = if last src == ' ' then init src else src
    s <- readFile src'
    case P.parse pFile "(unknown)" s of
        Right x -> do
                putStrLn "Enter function address"
                entry <- getLine
                let entryAddr = encodeWord64 $ toEnum (read entry :: Int)
                putStrLn "Enter arguments"
                args <- getLine
                let numbers = map read (lines args) :: [Int]
                let regs = foldr (\(a,v) r -> setReg r a v) emptyReg (zip [arg0,arg1,arg2,arg3,arg4,arg5] (map (encodeWord64 . toEnum) numbers))
                let (_,regs',_) = run (fst x) (M.empty,regs,M.empty) entryAddr entryAddr
                --print regs'
                let ret = decodeWord32 $ getReg regs' retVal 4
                putStrLn "Return value of called function is:"
                print ret
                -- print (run (fst x) (M.empty,regs,M.empty) (show entryAddr) entryAddr) -- 4294971152
                return ()
        Left _ -> do
                putStrLn "Parse error"
                return ()