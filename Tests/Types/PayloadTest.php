<?php
/**
 * This file is part of DoctrineRestDriver.
 *
 * DoctrineRestDriver is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * DoctrineRestDriver is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with DoctrineRestDriver.  If not, see <http://www.gnu.org/licenses/>.
 */

namespace Circle\DoctrineRestDriver\Tests\Types;

use Circle\DoctrineRestDriver\Types\Payload;
use PHPSQLParser\PHPSQLParser;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;

/**
 * Tests the payload type
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 */
#[CoversClass(Payload::class)]
#[CoversMethod(Payload::class,'create')]
class PayloadTest extends \PHPUnit\Framework\TestCase {

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function createInsert() {
        $parser   = new PHPSQLParser();
        $tokens   = $parser->parse('INSERT INTO products (name, value) VALUES (testname, testvalue)');
        $expected = json_encode([
            'name'  => 'testname',
            'value' => 'testvalue',
        ]);

        $this->assertSame($expected, Payload::create($tokens, []));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function createUpdate() {
        $parser   = new PHPSQLParser();
        $tokens   = $parser->parse('UPDATE products set name="testname", value="testvalue" WHERE id=1');
        $expected = json_encode([
            'name'  => 'testname',
            'value' => 'testvalue',
        ]);

        $this->assertSame($expected, Payload::create($tokens, []));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function createSelect() {
        $parser   = new PHPSQLParser();
        $tokens   = $parser->parse('SELECT name FROM products WHERE id=1');

        $this->assertSame(null, Payload::create($tokens, []));
    }
}
