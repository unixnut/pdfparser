<?php

/**
 * Portions of this file is based on code of phpseclib library.
 *
 * @see https://github.com/phpseclib/phpseclib/blob/master/phpseclib/Crypt/RC4.php
 *
 * Original code was licensed on the terms of the MIT License.
 *
 * ------------------------------------------------------------------------------
 *
 * @file This file is part of the PdfParser library.
 *
 * @author  Alastair Irvine <alastair@plug.org.au>
 *
 * @date    2024-01-12
 *
 * @license LGPLv3
 *
 * @url     <https://github.com/smalot/pdfparser>
 *
 *  PdfParser is a pdf library written in PHP, extraction oriented.
 *  Copyright (C) 2017 - Sébastien MALOT <sebastien@malot.fr>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this program.
 *  If not, see <http://www.pdfparser.org/sites/default/LICENSE.txt>.
 */

namespace Smalot\PdfParser\Encryption;

/**
 * Handles data decoding, decryption & ciphers, extra parsing, etc.
 */
class RC4
{
    public const ENCRYPT = 0;
    public const DECRYPT = 1;

    private $continuousBuffer = false;

    /**
     * Checks if OpenSSL on this platform supports RC4 ciphers.
     */
    function __construct(bool $forceCustom = false)
    {
        // Can't use openssl_get_cipher_methods() because the result includes
        // 'rc4' and 'rc4-40' even when they fail

        if ($forceCustom)
        {
            $this->useCustomAlg = true;
        }
        else
        {
            $data = "hello";
            $key = "................";
            $c = \openssl_encrypt($data, "RC4-40", $key, OPENSSL_RAW_DATA | OPENSSL_NO_PADDING);
            // It either failed or returned a string
            $this->useCustomAlg = ($c === false);
        }
    }


    public function encrypt(string $plaintext, string $key): string
    {
        if ($this->useCustomAlg)
        {
            $this->setupKey($key);
            return $this->crypt($plaintext, self::ENCRYPT);
        }
        else
        {
            return \openssl_encrypt($plaintext, "RC4-40", $key, OPENSSL_RAW_DATA | OPENSSL_NO_PADDING);
        }
    }


    public function decrypt(string $cyphertext, string $key): string
    {
        if ($this->useCustomAlg)
        {
            $this->setupKey($key);
            return $this->crypt($cyphertext, self::DECRYPT);
        }
        else
        {
            return \openssl_decrypt($cyphertext, "RC4-40", $key, OPENSSL_RAW_DATA | OPENSSL_NO_PADDING);
        }
    }


    /**
     * Setup the key (expansion)
     *
     * @author    Jim Wigginton <terrafrost@php.net>
     * @copyright 2007 Jim Wigginton
     * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
     * @link      https://github.com/phpseclib/phpseclib
     */
    protected function setupKey(string $key): void
    {
        //# $key = $this->key;
        $keyLength = strlen($key);
        $keyStream = range(0, 255);
        $j = 0;
        for ($i = 0; $i < 256; $i++) {
            $j = ($j + $keyStream[$i] + ord($key[$i % $keyLength])) & 255;
            $temp = $keyStream[$i];
            $keyStream[$i] = $keyStream[$j];
            $keyStream[$j] = $temp;
        }

        $this->stream = [];
        $this->stream[self::DECRYPT] = $this->stream[self::ENCRYPT] = [
            0, // index $i
            0, // index $j
            $keyStream,
        ];
    }

    /**
     * Encrypts or decrypts a message.
     *
     * @return string $text
     *
     * @author    Jim Wigginton <terrafrost@php.net>
     * @copyright 2007 Jim Wigginton
     * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
     * @link      https://github.com/phpseclib/phpseclib
     */
    private function crypt(string $text, int $mode): string
    {
        $stream = &$this->stream[$mode];
        if ($this->continuousBuffer) {
            $i = &$stream[0];
            $j = &$stream[1];
            $keyStream = &$stream[2];
        } else {
            $i = $stream[0];
            $j = $stream[1];
            $keyStream = $stream[2];
        }

        $len = strlen($text);
        for ($k = 0; $k < $len; ++$k) {
            $i = ($i + 1) & 255;
            $ksi = $keyStream[$i];
            $j = ($j + $ksi) & 255;
            $ksj = $keyStream[$j];

            $keyStream[$i] = $ksj;
            $keyStream[$j] = $ksi;
            $text[$k] = $text[$k] ^ chr($keyStream[($ksj + $ksi) & 255]);
        }

        return $text;
    }
}


# vim: set tabstop=4 shiftwidth=4 :
# Local Variables:
# tab-width: 4
# end:
