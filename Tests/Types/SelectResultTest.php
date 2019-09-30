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

use Circle\DoctrineRestDriver\Types\SelectResult;
use PHPSQLParser\PHPSQLParser;

/**
 * Tests the select result type
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 * @coversDefaultClass Circle\DoctrineRestDriver\Types\SelectResult
 */
class SelectResultTest extends \PHPUnit\Framework\TestCase {

    /**
     * @test
     * @group  unit
     * @covers ::create
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function createSingle() {
        $query  = 'SELECT name FROM products WHERE id=1';
        $parser = new PHPSQLParser();
        $tokens = $parser->parse($query);

        $content = [
            'name' => 'username'
        ];

        $expected = [
            [
                'name' => 'username'
            ]
        ];

        $this->assertEquals($expected, SelectResult::create($tokens, $content));
    }

    /**
     * @test
     * @group  unit
     * @covers ::create
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function createAll() {
        $query  = 'SELECT `name`, age FROM products';
        $parser = new PHPSQLParser();
        $tokens = $parser->parse($query);

        $content = [
            [
                'name' => 'username',
                'age'  => 18,
            ],
            [
                'name' => 'anotherUser',
                'age'  => 45,
            ],
        ];

        $expected = [
            [
                'name' => 'username',
                'age'  => 18,
            ],
            [
                'name' => 'anotherUser',
                'age'  => 45,
            ],
        ];

        $this->assertEquals($expected, SelectResult::create($tokens, $content));
    }
}
