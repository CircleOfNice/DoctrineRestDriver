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

use Circle\DoctrineRestDriver\Types\UpdateChangeSet;
use PHPSQLParser\PHPSQLParser;

/**
 * Tests the UpdateChangeSet type
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 * @coversDefaultClass Circle\DoctrineRestDriver\Types\UpdateChangeSet
 */
class UpdateChangeSetTest extends \PHPUnit\Framework\TestCase {

    /**
     * @test
     * @group  unit
     * @covers ::create
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function create() {
        $parser   = new PHPSQLParser();
        $tokens   = $parser->parse('UPDATE products set `name`="test,name", value="testvalue" WHERE id=1');
        $expected = [
            'name'  => 'test,name',
            'value' => 'testvalue',
        ];

        $this->assertSame($expected, UpdateChangeSet::create($tokens));
    }
    
    /**
     * @test
     * @group  unit
     * @covers ::create
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function createRemovesWhitespace() {
        $parser   = new PHPSQLParser();
        $tokens   = $parser->parse('UPDATE products set name = "test,name", `value` = "x=2" WHERE `id` = 1');
        $expected = [
            'name'  => 'test,name',
            'value' => 'x=2',
        ];

        $this->assertSame($expected, UpdateChangeSet::create($tokens));
    }
}
