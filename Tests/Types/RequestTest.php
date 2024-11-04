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

use Circle\DoctrineRestDriver\Types\Request;
use Circle\DoctrineRestDriver\Types\RestClientOptions;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;

/**
 * Tests the request type
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 */
#[CoversClass(Request::class)]
#[CoversMethod(Request::class,'__construct')]
#[CoversMethod(Request::class,'getMethod')]
#[CoversMethod(Request::class,'getUrl')]
#[CoversMethod(Request::class,'getUrlAndQuery')]
#[CoversMethod(Request::class,'getPayload')]
#[CoversMethod(Request::class,'getQuery')]
#[CoversMethod(Request::class,'getCurlOptions')]
#[CoversMethod(Request::class,'isExpectedStatusCode')]
#[CoversMethod(Request::class,'__toString')]
#[CoversMethod(Request::class,'setCurlOptions')]
class RequestTest extends \PHPUnit\Framework\TestCase {

    #[Test]
    #[Group('unit')]
    public function constructAndGetAll() {
        $options = [];

        $request = new Request([
            'method'      => 'get',
            'url'         => 'http://circle.ai',
            'curlOptions' => $options,
            'query'       => 'genious=1'
        ]);

        $this->assertSame('get', $request->getMethod());
        $this->assertSame('http://circle.ai', $request->getUrl());
        $this->assertSame('http://circle.ai?genious=1', $request->getUrlAndQuery());
        $this->assertSame(null, $request->getPayload());
        $this->assertSame('genious=1', $request->getQuery());
        $this->assertSame('GET http://circle.ai?genious=1 HTTP/1.1', $request->__toString());
        $this->assertEquals([], $request->getCurlOptions());
        $this->assertTrue($request->isExpectedStatusCode(200));
    }

    #[Test]
    #[Group('unit')]
    public function setCurlOptions() {
        $options = [
            'CURLOPT_HEADER' => true
        ];

        $expected = new Request([
            'method'      => 'get',
            'url'         => 'http://circle.ai',
            'curlOptions' => $options,
            'query'       => 'genious=1'
        ]);

        $request = new Request([
            'method'      => 'get',
            'url'         => 'http://circle.ai',
            'curlOptions' => [],
            'query'       => 'genious=1'
        ]);

        $this->assertEquals($expected, $request->setCurlOptions($options));
    }
}
