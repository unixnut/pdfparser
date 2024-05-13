<?php

declare(strict_types=1);

namespace PHPUnitTests\Unit\Encryption;

use PHPUnitTests\TestCase;


class TestOlderEncryption extends TestCase
{
    /**
     * An array of encryption metadata extracted by RawDataParser
     */
    private static $encryptArr = [
        [ '<<',
            [
                [ '/', 'Length', 1403 ],
                [ 'numeric', '128', 1407 ],
                [ '/', 'Filter', 1414 ],
                [ '/', 'Standard', 1423 ],
                [ '/', 'O', 1425 ],
                [ '(', "\x9e\xa2\x9a\xfd\x75\xae\xbc\x39\xb0\x5e\x23\xdd\x1f\x8e\x6c\x9d\x65\x67\x64\x0a\xec\x19\x0c\x36\x40\xb3\xc8\xdd\x97\x9f\x0e\x15", 1460 ],
                [ '/', 'P', 1462 ],
                [ 'numeric', '-1340', 1468 ],
                [ '/', 'R', 1470 ],
                [ 'numeric', '3', 1472 ],
                [ '/', 'U', 1474 ],
                [ '(', "\xe3\xe3\x50\xbf\x2e\x72\xa9\xb5\x24\x3f\xee\x70\x4d\xa4\xec\x16\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 1508 ],
                [ '/', 'V', 1510 ],
                [ 'numeric', '2', 1512 ],
            ],
            1514,
        ]
    ];

    /**
     * Extracted by RawDataParser
     */
    private static $fileIdArr = [
        'C21F21EA44C1E2ED2581435FA5A2DCCE',
        '15349106D985DA44991099F9C0CBF004'
    ];

    /**
     * Start with garbage metadata and ensure that it causes a failure.
     */
    public function testFileKeyInvalid(): void
    {
        $badFileIdArr = [
            '6e69652067696539726f3952692a2061',
            '694b396f65786061680a45654a3e6965'
        ];

        $this->expectException(\Smalot\PdfParser\Encryption\InvalidPassword::class);
        $info = new \Smalot\PdfParser\Encryption\Info(self::$encryptArr, $badFileIdArr);
        // This combines making the key and calling testFileKey()
        $fileKey = \Smalot\PdfParser\Encryption\FileKey::generate($info);
    }

    public function testMakeFileKey(): void
    {
        $knownKey = "\xf8\xa9\x65\xdf\xe9\xa9\x94\x95\xcd\x52\xb6\xad\x68\xcd\xa9\x43";

        //# [
        //#     'V' => ,  // version
        //#     'R' => ,  // revision
        //#     'Len' => ,  // length
        //#     'O' => ,  // ownerKey
        //#     'U' => ,  // userKey
        //#     'OE' => ,  // ownerEnc
        //#     'UE' => ,  // userEnc
        //#     'P' => ,  // perms
        //#     'encryptMetadata' => true,
        //# ];

        $info = new \Smalot\PdfParser\Encryption\Info(self::$encryptArr, self::$fileIdArr);
        // This combines making the key and calling testFileKey()
        $fileKey = \Smalot\PdfParser\Encryption\FileKey::generate($info);

        $this->assertTrue($fileKey === $knownKey, "Generated key does not match expected value");
    }
}


# vim: set tabstop=4 shiftwidth=4 :
# Local Variables:
# tab-width: 4
# end:
