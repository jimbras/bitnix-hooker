<?php declare(strict_types=1);

/**
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as
 *  published by the Free Software Foundation, either version 3 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/agpl-3.0.txt>.
 */

namespace Bitnix\Hooker;

use JsonException,
    Throwable;

/**
 * @version 0.1.0
 */
final class Guard implements Packer {

    private const HASH_ALGO = 'SHA256';
    private const HASH_LEN  = 32;
    private const SALT_LEN  = 16;

    /**
     * @param string $key
     * @param array $content
     * @return array
     * @throws PackerError
     */
    public function pack(string $key, array $content) : array {
        try {
            $salt = \random_bytes(self::SALT_LEN);
            $json = \json_encode($content, \JSON_THROW_ON_ERROR);
            $hash = \hash_hmac(self::HASH_ALGO, $json, $salt . $key, true);
            return [\base64_encode($hash . $salt), $json];
        } catch (Throwable $x) {
            throw new PackerError($x->getMessage());
        }
    }

    /**
     * @param string $key
     * @param string $hash
     * @param string $content
     * @return array
     * @throws PackerError
     */
    public function unpack(string $key, string $hash, string $content) : array {
        try {
            $secret = \base64_decode($hash);
            $hash = (string) \substr($secret, 0, self::HASH_LEN);
            $salt = (string) \substr($secret, -self::SALT_LEN);

            if (!\hash_equals($hash, \hash_hmac(self::HASH_ALGO, $content, $salt . $key, true))) {
                throw new PackerError('Payload hash validation error');
            }

            return \json_decode($content, true, 512, \JSON_THROW_ON_ERROR);
        } catch (PackerError $px) {
            throw $px;
        } catch (Throwable $x) {
            throw new PackerError($x->getMessage());
        }
    }

    /**
     * @return string
     */
    public function __toString() : string {
        return self::CLASS;
    }
}
