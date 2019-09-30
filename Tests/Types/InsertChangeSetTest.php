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

use Circle\DoctrineRestDriver\Types\InsertChangeSet;
use PHPSQLParser\PHPSQLParser;

/**
 * Tests the insert change set type
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 * @coversDefaultClass Circle\DoctrineRestDriver\Types\InsertChangeSet
 */
class InsertChangeSetTest extends \PHPUnit\Framework\TestCase {

    /**
     * @test
     * @group  unit
     * @covers ::create
     * @covers ::<private>
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function createWithRawValues() {
        $parser   = new PHPSQLParser();
        $tokens   = $parser->parse('INSERT INTO products (`name`, value) VALUES (testname, testvalue)');
        $expected = [
            'name'  => 'testname',
            'value' => 'testvalue',
        ];

        $this->assertSame($expected, InsertChangeSet::create($tokens));
    }

    /**
     * @test
     * @group  unit
     * @covers ::create
     * @covers ::<private>
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function createWithQuotedValuesWithWhiteSpaces() {
        $parser   = new PHPSQLParser();
        $tokens   = $parser->parse("INSERT INTO products (name, value) VALUES (' testname\n', `testvalue`)");
        $expected = [
            'name'  => " testname\n",
            'value' => 'testvalue',
        ];

        $this->assertSame($expected, InsertChangeSet::create($tokens));
    }

    /**
     * @test
     * @group  unit
     * @covers ::create
     * @covers ::<private>
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function createWithQuotesInQuotedValues() {
        $parser   = new PHPSQLParser();
        $tokens   = $parser->parse('INSERT INTO products (name, value, foo) VALUES ("test,name", `testvalue`, \'b\'\'ar\')');
        $expected = [
            'name'  => 'test,name',
            'value' => 'testvalue',
            'foo'   => 'b\'ar',
        ];

        $this->assertSame($expected, InsertChangeSet::create($tokens));
    }

    /**
     * @test
     * @group  unit
     * @covers ::create
     * @covers ::<private>
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function createWithSurroundingQuotedValues() {
        $parser   = new PHPSQLParser();
        $tokens   = $parser->parse("INSERT INTO products (name) VALUES ('''test,name''')");
        $expected = [
            'name'  => '\'test,name\'',
        ];

        $this->assertSame($expected, InsertChangeSet::create($tokens));
    }

    /**
     * @test
     * @group  unit
     * @covers ::create
     * @covers ::<private>
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function createWithIntValue() {
        $parser   = new PHPSQLParser();
        $tokens   = $parser->parse('INSERT INTO products (name, value) VALUES (testname, 1)');
        $expected = [
            'name'  => 'testname',
            'value' => 1,
        ];

        $this->assertSame($expected, InsertChangeSet::create($tokens));
    }

    /**
     * @test
     * @group  unit
     * @covers ::values
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function values() {
        $parser   = new PHPSQLParser();
        $tokens   = $parser->parse('INSERT INTO products (name, value) VALUES (testname, testvalue)');
        $expected = ['testname', 'testvalue'];

        $this->assertEquals($expected, InsertChangeSet::values($tokens));
    }

    /**
     * @test
     * @group  unit
     * @covers ::columns
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function columns() {
        $parser   = new PHPSQLParser();
        $tokens   = $parser->parse('INSERT INTO products (name, value) VALUES (testname, testvalue)');
        $expected = ['name', 'value'];

        $this->assertEquals($expected, InsertChangeSet::columns($tokens));
    }
}
