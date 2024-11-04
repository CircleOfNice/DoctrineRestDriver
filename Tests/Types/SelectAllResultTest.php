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

use Circle\DoctrineRestDriver\Types\SelectAllResult;
use Circle\DoctrineRestDriver\Types\SelectSingleResult;
use PHPSQLParser\PHPSQLParser;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;

/**
 * Tests the select all result type
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 */
#[CoversClass(SelectAllResult::class)]
#[CoversMethod(SelectAllResult::class,'create')]
#[CoversMethod(SelectAllResult::class,'orderBy')]

class SelectAllResultTest extends \PHPUnit\Framework\TestCase {

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function create() {
        $query  = 'SELECT name FROM products';
        $parser = new PHPSQLParser();
        $tokens = $parser->parse($query);

        $content = [
            [
                'name' => 'username'
            ],
            [
                'name' => 'anotherUser'
            ],
        ];

        $expected = [
            [
                'name' => 'username'
            ],
            [
                'name' => 'anotherUser'
            ],
        ];

        $this->assertEquals($expected, SelectAllResult::create($tokens, $content));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function selectAllOrderBy() {
        $query  = 'SELECT name FROM products ORDER BY name';
        $parser = new PHPSQLParser();
        $tokens = $parser->parse($query);

        $content = [
            [
                'name' => 'username'
            ],
            [
                'name' => 'anotherUser'
            ],
        ];

        $expected = [
            [
                'name' => 'anotherUser'
            ],
            [
                'name' => 'username'
            ],
        ];

        $this->assertEquals($expected, SelectAllResult::create($tokens, $content));
    }
}
