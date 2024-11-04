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

namespace Circle\DoctrineRestDriver\Tests\Factory;

use Circle\DoctrineRestDriver\Factory\RequestFactory;
use Circle\DoctrineRestDriver\Types\Request;
use PHPSQLParser\PHPSQLParser;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;

/**
 * Tests the restclient factory
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 */
#[CoversClass(RequestFactory::class)]
#[CoversMethod(RequestFactory::class, 'createOne')]
class RequestFactoryTest extends \PHPUnit\Framework\TestCase {

    /**
     * @var array
     */
    private $requestOptions = [
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
        CURLOPT_MAXREDIRS      => 25,
        CURLOPT_TIMEOUT        => 25,
        CURLOPT_CONNECTTIMEOUT => 25,
        CURLOPT_CRLF           => true,
        CURLOPT_SSLVERSION     => 3,
        CURLOPT_FOLLOWLOCATION => true,
    ];

    /**
     * @var array
     */
    private $factoryOptions = [
        'host'          => 'http://circle.ai',
        'driverOptions' => [
            'CURLOPT_HTTPHEADER'     => 'Content-Type: application/json',
            'CURLOPT_MAXREDIRS'      => 25,
            'CURLOPT_TIMEOUT'        => 25,
            'CURLOPT_CONNECTTIMEOUT' => 25,
            'CURLOPT_CRLF'           => true,
            'CURLOPT_SSLVERSION'     => 3,
            'CURLOPT_FOLLOWLOCATION' => true,
        ]
    ];

    #[Test]
    #[Group('unit')]
    public function createOne() {
        $query    = 'SELECT name FROM products t0 WHERE t0.id=1';
        $parser   = new PHPSQLParser();
        $factory  = new RequestFactory();
        $expected = new Request([
            'method'              => 'get',
            'url'                 => 'http://circle.ai/products/1',
            'curlOptions'         => $this->requestOptions,
            'expectedStatusCodes' => [200, 203, 206, 404]
        ]);

        $routings = $this->getMockBuilder('Circle\DoctrineRestDriver\Annotations\DataSource')->getMock();

        $this->assertEquals($expected, $factory->createOne('get', $parser->parse($query), $this->factoryOptions, $routings));
    }

    #[Test]
    #[Group('unit')]
    public function createOneWithPaginationHeadersDefault() {
        $query    = 'SELECT name FROM products WHERE LIMIT 5 OFFSET 10';
        $parser   = new PHPSQLParser();
        $factory  = new RequestFactory();
        $this->requestOptions[CURLOPT_HTTPHEADER][] = 'Limit: 5';
        $this->requestOptions[CURLOPT_HTTPHEADER][] = 'Offset: 10';
        $expected = new Request([
            'method'              => 'get',
            'url'                 => 'http://circle.ai/products',
            'curlOptions'         => $this->requestOptions,
            'query'               => '',
            'expectedStatusCodes' => [200, 203, 206, 404]
        ]);

        $routings = $this->getMockBuilder('Circle\DoctrineRestDriver\Annotations\DataSource')->getMock();

        $this->assertEquals($expected, $factory->createOne('get', $parser->parse($query), $this->factoryOptions, $routings));
    }

    #[Test]
    #[Group('unit')]
    public function createWithPaginationParameters() {
        $query    = 'SELECT name FROM products WHERE LIMIT 5 OFFSET 10';
        $parser   = new PHPSQLParser();
        $factory  = new RequestFactory();
        $this->factoryOptions['driverOptions']['pagination_as_query'] = true;
        $expected = new Request([
            'method'              => 'get',
            'url'                 => 'http://circle.ai/products',
            'curlOptions'         => $this->requestOptions,
            'query'               => 'per_page=5&page=3',
            'expectedStatusCodes' => [200, 203, 206, 404]
        ]);

        $routings = $this->getMockBuilder('Circle\DoctrineRestDriver\Annotations\DataSource')->getMock();

        $this->assertEquals($expected, $factory->createOne('get', $parser->parse($query), $this->factoryOptions, $routings));
    }
}
