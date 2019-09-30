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

use Circle\DoctrineRestDriver\Types\Url;
use PHPSQLParser\PHPSQLParser;

/**
 * Tests the url type
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 * @coversDefaultClass Circle\DoctrineRestDriver\Types\Url
 */
class UrlTest extends \PHPUnit\Framework\TestCase {

    /**
     * @test
     * @group  unit
     * @covers ::create
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function create() {
        $this->assertSame('http://circle.ai/products/1', Url::create('products', 'http://circle.ai', '1'));
    }

    /**
     * @test
     * @group  unit
     * @covers ::create
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function createWithUrl() {
        $this->assertSame('http://www.circle.ai/products/1', Url::create('http://www.circle.ai/products/{id}', 'http://circle.ai', '1'));
    }

    /**
     * @test
     * @group  unit
     * @covers ::create
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function createWithUrlWithoutSetId() {
        $this->assertSame('http://www.circle.ai/products', Url::create('http://www.circle.ai/products/{id}', 'http://circle.ai'));
    }

    /**
     * @test
     * @group  unit
     * @covers ::create
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function createWithoutAnyId() {
        $this->assertSame('http://www.circle.ai/products/1', Url::create('http://www.circle.ai/products', 'http://circle.ai', '1'));
    }

    /**
     * Provides queries and expected url's
     *
     * @see UrlTest::createFromTokens()
     *
     * @return array
     */
    public function queryUrlProvider() {
        return [
            ['SELECT name FROM products WHERE id=1', 'http://circle.ai/products/1'],
            ['SELECT name FROM products WHERE id="foo"', 'http://circle.ai/products/foo'],
            ['SELECT name FROM products WHERE id="\\Foo\\bar"', 'http://circle.ai/products/%5CFoo%5Cbar'],
            ['SELECT name FROM products WHERE id="id with space"', 'http://circle.ai/products/id%20with%20space'],
        ];
    }

    /**
     * @test
     * @group  unit
     * @covers ::createFromTokens
     * @dataProvider queryUrlProvider
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     *
     * @param $query
     * @param $expectedUrl
     */
    public function createFromTokens($query, $expectedUrl) {
        $tokens     = (new PHPSQLParser())->parse($query);
        $annotation = $this->getMockBuilder('Circle\DoctrineRestDriver\Annotations\DataSource')->getMock();
        $annotation
            ->expects($this->exactly(2))
            ->method('getRoute')
            ->will($this->returnValue('http://circle.ai/products/{id}'));

        $this->assertSame($expectedUrl, Url::createFromTokens($tokens, 'http://circle.ai', $annotation));
        $this->assertSame($expectedUrl, Url::createFromTokens($tokens, 'http://circle.ai'));
    }

    /**
     * @test
     * @group  unit
     * @covers ::is
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function isTest() {
        $this->assertTrue(Url::is('http://www.circle.ai'));
    }

    /**
     * @test
     * @group  unit
     * @covers ::is
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function isUrlLocalhostTest() {
        $this->assertTrue(Url::is('http://localhost:3000'));
        $this->assertTrue(Url::is('http://localhost:3000/api?filter=true'));
    }

    /**
     * @test
     * @group  unit
     * @covers ::is
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function isNoUrlTest() {
        $this->assertFalse(Url::is('http:/localhost:3000'));
        $this->assertFalse(Url::is('localhost:3000'));
        $this->assertFalse(Url::is('www.circle.ai'));
        $this->assertFalse(Url::is('noUrl'));
        $this->assertFalse(Url::is(1));
    }

    /**
     * @test
     * @group  unit
     * @covers ::assert
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function assert() {
        $this->assertSame('http://www.test.com', Url::assert('http://www.test.com', 'Url'));
        $this->assertSame('http://www.test.com?filter=1', Url::assert('http://www.test.com?filter=1', 'Url'));
        $this->assertSame('http://circle.ai', Url::assert('http://circle.ai', 'Url'));
        $this->assertSame('http://circle.ai/test?test=test', Url::assert('http://circle.ai/test?test=test', 'Url'));
    }

    /**
     * @test
     * @group  unit
     * @covers ::assert
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     * @expectedException \Circle\DoctrineRestDriver\Validation\Exceptions\InvalidTypeException
     */
    public function assertUrlOnException() {
        Url::assert('localhost:3000', 'Url');
    }
}
