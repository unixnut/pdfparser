<?php

declare(strict_types=1);

namespace PHPUnitTests\Unit\Encryption;

require_once '/home/alastair/src/unixnut_pdfparser/vendor/autoload.php';

use PHPUnitTests\TestCase;


class TestRC4 extends TestCase
{
    public function setup(): void
    {
        $this->rc4 = new \Smalot\PdfParser\Encryption\RC4(true);
    }


    /**
     * Ensure that a given string encrypts to a known cyphertext.
     */
    public function testEncrypt(): void
    {
        $data = "hello";
        $key = "................";
        $result = $this->rc4->encrypt($data, $key);
        $this->assertEquals(strlen($data), strlen($result), "Output doesn't match length of plaintext");
        $this->assertEquals("156bd1e9e9", bin2hex($result), "Incorrect cyphertext produced");
    }


    /**
     * Ensure that a known cyphertext decrypts to the same string as for testEncrypt().
     */
    public function testDecrypt(): void
    {
        $data = "\x15\x6b\xd1\xe9\xe9"; // Encrypted string
        $key = "................";
        $result = $this->rc4->decrypt($data, $key);
        $this->assertEquals("hello", $result, "Cyphertext not decrypted");
    }
}



# vim: set tabstop=4 shiftwidth=4 :
# Local Variables:
# tab-width: 4
# end:
