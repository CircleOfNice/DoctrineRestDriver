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
use Circle\DoctrineRestDriver\Validation\Exceptions\InvalidTypeException;
use PHPSQLParser\PHPSQLParser;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;

/**
 * Tests the url type
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 */
#[CoversClass(Url::class)]
#[CoversMethod(Url::class,'create')]
#[CoversMethod(Url::class,'createFromTokens')]
#[CoversMethod(Url::class,'is')]
#[CoversMethod(Url::class,'assert')]
class UrlTest extends \PHPUnit\Framework\TestCase {

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function create() {
        $this->assertSame('http://circle.ai/products/1', Url::create('products', 'http://circle.ai', '1'));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function createWithUrl() {
        $this->assertSame('http://www.circle.ai/products/1', Url::create('http://www.circle.ai/products/{id}', 'http://circle.ai', '1'));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function createWithUrlWithoutSetId() {
        $this->assertSame('http://www.circle.ai/products', Url::create('http://www.circle.ai/products/{id}', 'http://circle.ai'));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function createWithoutAnyId() {
        $this->assertSame('http://www.circle.ai/products/1', Url::create('http://www.circle.ai/products', 'http://circle.ai', '1'));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function createFromTokens() {
        $tokens     = (new PHPSQLParser())->parse('SELECT name FROM products WHERE id=1');
        $annotation = $this->getMockBuilder('Circle\DoctrineRestDriver\Annotations\DataSource')->getMock();
        $annotation
            ->expects($this->exactly(2))
            ->method('getRoute')
            ->willReturn('http://circle.ai/products/{id}');

        $this->assertSame('http://circle.ai/products/1', Url::createFromTokens($tokens, 'http://circle.ai', $annotation));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function isTest() {
        $this->assertTrue(Url::is('http://www.circle.ai'));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function isUrlLocalhostTest() {
        $this->assertTrue(Url::is('http://localhost:3000'));
        $this->assertTrue(Url::is('http://localhost:3000/api?filter=true'));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function isNoUrlTest() {
        $this->assertFalse(Url::is('http:/localhost:3000'));
        $this->assertFalse(Url::is('localhost:3000'));
        $this->assertFalse(Url::is('www.circle.ai'));
        $this->assertFalse(Url::is('noUrl'));
        $this->assertFalse(Url::is(1));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function assert() {
        $this->assertSame('http://www.test.com', Url::assert('http://www.test.com', 'Url'));
        $this->assertSame('http://www.test.com?filter=1', Url::assert('http://www.test.com?filter=1', 'Url'));
        $this->assertSame('http://circle.ai', Url::assert('http://circle.ai', 'Url'));
        $this->assertSame('http://circle.ai/test?test=test', Url::assert('http://circle.ai/test?test=test', 'Url'));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function assertUrlOnException() {
        $this->expectException(InvalidTypeException::class);
        Url::assert('localhost:3000', 'Url');
    }
}
