<?php

declare(strict_types=1);

namespace PHPUnitTests\Unit\Encryption;

use PHPUnitTests\TestCase;
use Smalot\PdfParser\Document;
use Smalot\PdfParser\Encoding;
use Smalot\PdfParser\Encryption;


class TestRev5PlusEncryption extends TestCase
{
    /**
     * An array of encryption metadata extracted by RawDataParser
     */
    private static $encryptArr = [
        [ '<<',
            [
                [ '/', 'CF', 20958 ],
                [ '<<',
                    [
                        [ '/', 'StdCF', 20966 ],
                        [ '<<',
                            [
                                [ '/', 'AuthEvent', 20978 ],
                                [ '/', 'DocOpen', 20986 ],
                                [ '/', 'CFM', 20990 ],
                                [ '/', 'AESV3', 20996 ],
                                [ '/', 'Length', 21003 ],
                                [ 'numeric', '32', 21006 ]
                            ], 21008
                        ],
                    ], 21010
                ],
                [ '/', 'EncryptMetadata', 21026 ],
                [ 'boolean', 'true', 21031 ],
                [ '/', 'Filter', 21038 ],
                [ '/', 'Standard', 21047 ],
                [ '/', 'Length', 21054 ],
                [ 'numeric', '256', 21058 ],
                [ '/', 'O', 21060 ],
                [ '(', "\xa2\x2e\x03\x50\x16\x44\x96\x18\x3e\x95\xd9\xbc\x58\x34\xee\x8b\xa6\x88\xac\xcc\xdb\xf5\x7e\x75\x1f\x0e\x74\x45\xd7\x83\x44\x7b\x3b\x10\xe7\x16\x72\x01\xbd\x86\xd9\xcc\x89\x3c\x48\x55\x3a\xcf", 21110 ],
                [ '/', 'OE', 21113 ],
                [ '(', "\xcb\x90\xfd\xfb\xf4\x24\xc2\x9b\xfb\x20\x8f\x05\x3a\x2a\xe9\x74\x47\x68\xdd\x76\xcf\xa4\x83\xa4\x84\xe0\x81\xfe\x95\xe5\x7e\x3b", 21147 ],
                [ '/', 'P', 21149 ],
                [ 'numeric', '-3392', 21155 ],
                [ '/', 'Perms', 21161 ],
                [ '(', '', 21179 ],
                [ '/', 'R', 21181 ],
                [ 'numeric', '5', 21183 ],
                [ '/', 'StmF', 21188 ],
                [ '/', 'StdCF', 21194 ],
                [ '/', 'StrF', 21199 ],
                [ '/', 'StdCF', 21205 ],
                [ '/', 'U', 21207 ],
                [ '(', "\x2d\xc2\x90\x6c\xc8\x46\x15\x38\xe1\x1f\x4b\x98\xb2\xae\xb8\x8f\xa7\x97\x6f\xaa\xb0\xd4\xca\x02\xf1\xf5\xb4\x22\x65\xb1\xa0\x36\x3b\x10\xe7\x16\x72\x01\xbd\x86\xd9\xcc\x89\x3c\x48\x55\x3a\xcf", 21257 ],
                [ '/', 'UE', 21260 ],
                [ '(', "\xe2\x0f\x0a\x51\xbb\x9f\xe1\xf0\x22\x80\xe0\x40\xe0\x34\x8e\x1b\x6f\x6b\x36\x38\xd6\xe5\xa8\x55\xb9\x97\x2c\xfc\xa7\xf0\xe5\xec", 21295 ],
                [ '/', 'V', 21297 ],
                [ 'numeric', '5', 21299 ]
            ], 21301
        ]
    ];

    /**
     * Garbage data as the file ID is irrelevent for recent revisions.
     */
    private static $fileIdArr = [
        '6e69652067696539726f3952692a2061',
        '694b396f65786061680a45654a3e6965'
    ];

    /**
     * Start with garbage metadata and ensure that it causes a failure.
     */
    public function testPasswordInvalid(): void
    {
        // Tweak the raw metadata in a way that will cause ???????? to fail
        $badMetadata = self::$encryptArr;
        // ownerKey
        $this->assertEquals(21110, $badMetadata[0][1][9][2]);
        $badMetadata[0][1][9][1] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        // ownerEnc
        $this->assertEquals(21147, $badMetadata[0][1][11][2]);
        $badMetadata[0][1][11][1] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        // userKey
        $this->assertEquals(21257, $badMetadata[0][1][23][2]);
        $badMetadata[0][1][23][1] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        // userEnc
        $this->assertEquals(21295, $badMetadata[0][1][25][2]);
        $badMetadata[0][1][25][1] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

        $this->expectException(\Smalot\PdfParser\Encryption\InvalidPassword::class);
        $info = new \Smalot\PdfParser\Encryption\Info($badMetadata, self::$fileIdArr);
        // This combines password operations and making the key and calling testFileKey()
        $fileKey = \Smalot\PdfParser\Encryption\FileKey::generate($info);
    }

    /**
     * Start with a known good file key and ensure that it can be validated
     * with the encryption info's 'userEnc' field.
     */
    public function testFileKeyValid(): void
    {
        $knownKey = "\x3b\x10\xe7\x16\x72\x01\xbd\x86\xd9\xcc\x89\x3c\x48\x55\x3a\xcf\xbe\xbd\x4a\x0f\x7d\x57\x67\xf9\xeb\x0f\x08\xd2\xcc\xd3\x66\xa9";
        $info = new \Smalot\PdfParser\Encryption\Info(self::$encryptArr, self::$fileIdArr);
        $fileKey = \Smalot\PdfParser\Encryption\FileKey::generate($info);

        $this->assertTrue($fileKey === $knownKey, "Generated key does not match expected value");
    }
}


# vim: set tabstop=4 shiftwidth=4 :
# Local Variables:
# tab-width: 4
# end:
