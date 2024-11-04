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
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * Tests the result type
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 */
#[CoversClass(Result::class)]
#[CoversMethod(Result::class,'__construct')]
#[CoversMethod(Result::class,'get')]
#[CoversMethod(Result::class,'id')]
class ResultTest extends \PHPUnit\Framework\TestCase {

    /**
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function getWithSelect() {
        $response = new Response(json_encode([
            'name' => 'testname'
        ]));

        $expected = [
            [
                'name' => 'testname'
            ]
        ];

        $this->assertEquals($expected, (new Result('SELECT name FROM products WHERE id=1', 'get', $response))->get());
    }

    /**
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function getWithDelete() {
        $response = new Response(json_encode([
            'name' => 'testname'
        ]));

        $expected = [];

        $this->assertEquals($expected, (new Result('DELETE FROM products WHERE id=1', 'delete', $response))->get());
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function getWithInsert() {
        $response = new Response(json_encode([
            'name' => 'testname'
        ]));

        $expected = [
            'name' => 'testname'
        ];

        $this->assertEquals($expected, (new Result('INSERT INTO products (name) VALUES ("testname")', 'post', $response))->get());
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function getWithUpdate() {
        $response = new Response(json_encode([
            'name' => 'testname'
        ]));

        $expected = [
            'name' => 'testname'
        ];

        $this->assertEquals($expected, (new Result('UPDATE products SET name = "testname" WHERE id=1', 'patch', $response))->get());
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function id() {
        $response = new Response(json_encode([
            'name' => 'testname',
            'id'   => 1
        ]));

        $expected = 1;

        $this->assertEquals($expected, (new Result('UPDATE products SET name = "testname" WHERE id=1', 'put', $response))->id());
    }
}
