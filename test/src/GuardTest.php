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

use PHPUnit\Framework\TestCase;

/**
 * @version 0.1.0
 */
class GuardTest extends TestCase {

    public function testPack() {
        $guard = new Guard();

        $data = ['foo' => 'bar'];
        $secret = 's3cr3t_t0k3n';

        list($hash, $payload) = $guard->pack($secret, $data);
        $this->assertEquals($data, $guard->unpack($secret, $hash, $payload));
    }

    public function testPackError() {
        $this->expectException(PackerError::CLASS);
        $guard = new Guard();

        $data = [];
        $data['data'] = &$data;
        $secret = 's3cr3t_t0k3n';

        $guard->pack($secret, $data);
    }

    public function testUnpackInvalidTokenError() {
        $this->expectException(PackerError::CLASS);
        $guard = new Guard();

        $data = [];
        $secret = 's3cr3t_t0k3n';

        list($hash, $payload) = $guard->pack($secret, $data);
        $guard->unpack('xxx' . $secret, $hash, $payload);
    }

    public function testUnpackTamperedPayloadError() {
        $this->expectException(PackerError::CLASS);
        $guard = new Guard();

        $data = [];
        $secret = 's3cr3t_t0k3n';

        list($hash, $payload) = $guard->pack($secret, $data);
        $guard->unpack('xxx' . $secret, $hash, \json_encode(['foo' => 'bar']));
    }

    public function testUnpackPayloadDecodeError() {
        $this->expectException(PackerError::CLASS);

        $secret = 's3cr3t_t0k3n';

        $salt = \random_bytes(16);
        $json = '{bad:"json"}';
        $hash = \hash_hmac('SHA256', $json, $salt . $secret, true);

        $guard = new Guard();
        $guard->unpack($secret, \base64_encode($hash . $salt), $json);
    }

    public function testToString() {
        $this->assertIsString((string) new Guard());
    }

}
