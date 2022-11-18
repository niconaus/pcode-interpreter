{-|
Module      : WordString
Description : Word8 string helper functions
Copyright   : (c) Nico Naus, 2022
Maintainer  : niconaus@vt.edu
Stability   : experimental
This module defines several helper functions to perform operations on word8 strings
-}
module WordString where

import Data.Binary
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy as BS
import Data.Word
import Data.Binary.Get
import Data.Bits

-- Unsigned addition
uAdd :: [Word8] -> [Word8] -> [Word8]
uAdd w1 w2 | length w1 == 1 = encodeWord8  $ decodeWord8 w1  + decodeWord8 w2
           | length w1 == 2 = encodeWord16 $ decodeWord16 w1 + decodeWord16 w2
           | length w1 == 4 = encodeWord32 $ decodeWord32 w1 + decodeWord32 w2
           | length w1 == 8 = encodeWord64 $ decodeWord64 w1 + decodeWord64 w2
uAdd _ _ = error "addition not defined for this length"



--Sign extension
signExtend :: Word8 -> [Word8] -> [Word8]
signExtend i wx | length wx > fromEnum i = error "sign extend cannot shorten word"
                | otherwise = concat $ replicate (fromEnum i-length wx) (if getSign wx then [255] else [0]) ++ [wx]

zeroExtend :: Word8 -> [Word8] -> [Word8]
zeroExtend i wx | length wx > fromEnum i = error "unsigned extend cannot shorten word"
                | otherwise = replicate (fromEnum i-length wx) 0 ++ wx

getSign :: [Word8] -> Bool
getSign xs = testBit (last xs) 7

-- From and to Word

encodeWord8 :: Word8 -> [Word8]
encodeWord8 x = [x]

decodeWord8 :: [Word8] -> Word8
decodeWord8 [x] = x
decodeWord8 xs = error $ "Bytestring too long or short to be a word8: " ++ show xs

encodeWord16 :: Word16 -> [Word8]
encodeWord16 = BS.unpack . toLazyByteString . word16BE

decodeWord16 :: [Word8] -> Word16
decodeWord16 xs = runGet getWord16be (BS.pack xs)

encodeWord32 :: Word32 -> [Word8]
encodeWord32 = BS.unpack . toLazyByteString . word32BE

decodeWord32 :: [Word8] -> Word32
decodeWord32 xs = runGet getWord32be (BS.pack xs)

encodeWord64 :: Word64 -> [Word8]
encodeWord64 = BS.unpack . toLazyByteString . word64BE

decodeWord64 :: [Word8] -> Word64
decodeWord64 x = runGet getWord64be (BS.pack x)
