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

use Circle\DoctrineRestDriver\Types\Result;

/**
 * Tests the result type
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 * @coversDefaultClass Circle\DoctrineRestDriver\Types\Result
 */
class ResultTest extends \PHPUnit_Framework_TestCase {

    /**
     * @test
     * @group  unit
     * @covers ::create
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function createWithSelect() {
        $content = [
            'name' => 'testname'
        ];

        $expected = [
            [
                'name' => 'testname'
            ]
        ];

        $this->assertEquals($expected, Result::create('SELECT name FROM products WHERE id=1', $content));
    }

    /**
     * @test
     * @group  unit
     * @covers ::create
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function createWithSelectContainingFullUrl() {
        $content = [
            'name' => 'testname'
        ];

        $expected = [
            [
                't0.name' => 'testname'
            ]
        ];

        $this->assertEquals($expected, Result::create('SELECT t0.name FROM http://example.com/products t0', $content));
    }

    /**
     * @test
     * @group  unit
     * @covers ::create
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function createWithDelete() {
        $content = [
            'name' => 'testname'
        ];

        $expected = [];

        $this->assertEquals($expected, Result::create('DELETE FROM products WHERE id=1', $content));
    }

    /**
     * @test
     * @group  unit
     * @covers ::create
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function createWithInsert() {
        $content = [
            'name' => 'testname'
        ];

        $expected = [
            'name' => 'testname'
        ];

        $this->assertEquals($expected, Result::create('INSERT INTO products (name) VALUES ("testname")', $content));
    }

    /**
     * @test
     * @group  unit
     * @covers ::create
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function createWithUpdate() {
        $content = [
            'name' => 'testname'
        ];

        $expected = [
            'name' => 'testname'
        ];

        $this->assertEquals($expected, Result::create('UPDATE products SET name = "testname" WHERE id=1', $content));
    }
}