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

/**
 * @version 0.1.0
 */
interface Packer {

    /**
     * @param string $key
     * @param array $content
     * @return array
     * @throws PackerError
     */
    public function pack(string $key, array $content) : array;

    /**
     * @param string $key
     * @param string $hash
     * @param string $content
     * @return array
     * @throws PackerError
     */
    public function unpack(string $key, string $hash, string $content) : array;

}
