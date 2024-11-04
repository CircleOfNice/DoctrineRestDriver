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
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;

/**
 * Tests the insert change set type
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 */
#[CoversClass(InsertChangeSet::class)]
#[CoversMethod(InsertChangeSet::class,'create')]
#[CoversMethod(InsertChangeSet::class,'values')]
#[CoversMethod(InsertChangeSet::class,'columns')]

class InsertChangeSetTest extends \PHPUnit\Framework\TestCase {

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function createWithRawValues() {
        $parser   = new PHPSQLParser();
        $tokens   = $parser->parse('INSERT INTO products (name, value) VALUES (testname, testvalue)');
        $expected = [
            'name'  => 'testname',
            'value' => 'testvalue',
        ];

        $this->assertSame($expected, InsertChangeSet::create($tokens));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function createWithQuotedValues() {
        $parser   = new PHPSQLParser();
        $tokens   = $parser->parse('INSERT INTO products (name, value) VALUES ("testname", `testvalue`)');
        $expected = [
            'name'  => 'testname',
            'value' => 'testvalue',
        ];

        $this->assertSame($expected, InsertChangeSet::create($tokens));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
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
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function values() {
        $parser   = new PHPSQLParser();
        $tokens   = $parser->parse('INSERT INTO products (name, value) VALUES (testname, testvalue)');
        $expected = ['testname', 'testvalue'];

        $this->assertEquals($expected, InsertChangeSet::values($tokens));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function columns() {
        $parser   = new PHPSQLParser();
        $tokens   = $parser->parse('INSERT INTO products (name, value) VALUES (testname, testvalue)');
        $expected = ['name', 'value'];

        $this->assertEquals($expected, InsertChangeSet::columns($tokens));
    }
}
