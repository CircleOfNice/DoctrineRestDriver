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

namespace Circle\DoctrineRestDriver\Tests\Transformers;

use Circle\DoctrineRestDriver\Annotations\RoutingTable;
use Circle\DoctrineRestDriver\Transformers\MysqlToRequest;
use Circle\DoctrineRestDriver\Types\CurlOptions;
use Circle\DoctrineRestDriver\Types\Request;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;

/**
 * Tests the mysql to request transformer
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 * @coversDefaultClass Circle\DoctrineRestDriver\Transformers\MysqlToRequest
 * @SuppressWarnings("PHPMD.TooManyPublicMethods")
 */
#[CoversMethod(MysqlToRequest::class,'__construct')]
#[CoversMethod(MysqlToRequest::class,'transform')]
//#[CoversMethod(MysqlToRequest::class,'<private>')]
class MysqlToRequestTest extends \PHPUnit\Framework\TestCase {

    /**
     *
     * @var RoutingTable
     */
    private $routings;

    /**
     * @var string
     */
    private $apiUrl = 'http://www.test.de';

    /**
     * @var array
     */
    private $options = [
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
        CURLOPT_MAXREDIRS      => 25,
        CURLOPT_TIMEOUT        => 25,
        CURLOPT_CONNECTTIMEOUT => 25,
        CURLOPT_CRLF           => true,
        CURLOPT_SSLVERSION     => 3,
        CURLOPT_FOLLOWLOCATION => true,
    ];

    /**
     * {@inheritdoc}
     */
    public function setUp() : void {
        $this->routings = $this->getMockBuilder('Circle\DoctrineRestDriver\Annotations\RoutingTable')->disableOriginalConstructor()->getMock();
        $this->routings
            ->expects($this->any())
            ->method('get')
            ->willReturn(null);
    }

    /**
     * Create a MysqlToRequest instance with the given options.
     *
     * @param array $optionsOverride
     * @return MysqlToRequest
     *
     * @author Rob Treacy <email@roberttreacy.com>
     */
    private function createMysqlToRequest($optionsOverride = []) {
        $options = array_replace_recursive([
                'host'          => 'http://www.test.de',
                'driverOptions' => [
                    'CURLOPT_HTTPHEADER'     => 'Content-Type: application/json',
                    'CURLOPT_MAXREDIRS'      => 25,
                    'CURLOPT_TIMEOUT'        => 25,
                    'CURLOPT_CONNECTTIMEOUT' => 25,
                    'CURLOPT_CRLF'           => true,
                    'CURLOPT_SSLVERSION'     => 3,
                    'CURLOPT_FOLLOWLOCATION' => true,
                ]
            ], $optionsOverride);

        return new MysqlToRequest($options, $this->routings);
    }

    #[Test]
    #[Group('unit')]
    public function selectOne() {
        $query    = 'SELECT name FROM products t0 WHERE t0.id = 1';
        $expected = new Request([
            'method'              => 'get',
            'url'                 => $this->apiUrl . '/products/1',
            'curlOptions'         => $this->options,
            'expectedStatusCodes' => [200, 203, 206, 404]
        ]);

        $this->assertEquals($expected, $this->createMysqlToRequest()->transform($query));
    }

    #[Test]
    #[Group('unit')]
    public function selectOneBy() {
        $query    = 'SELECT name FROM products t0 WHERE t0.id=1 AND t0.name=myName';
        $expected = new Request([
            'method'              => 'get',
            'url'                 => $this->apiUrl . '/products/1',
            'curlOptions'         => $this->options,
            'query'               => 'name=myName',
            'expectedStatusCodes' => [200, 203, 206, 404]
        ]);

        $this->assertEquals($expected, $this->createMysqlToRequest()->transform($query));
    }

    #[Test]
    #[Group('unit')]
    public function selectBy() {
        $query    = 'SELECT name FROM products t0 WHERE t0.name=myName';
        $expected = new Request([
            'method'              => 'get',
            'url'                 => $this->apiUrl . '/products',
            'curlOptions'         => $this->options,
            'query'               => 'name=myName',
            'expectedStatusCodes' => [200, 203, 206, 404]
        ]);

        $this->assertEquals($expected, $this->createMysqlToRequest()->transform($query));
    }

    #[Test]
    #[Group('unit')]
    public function selectAll() {
        $query    = 'SELECT name FROM products';
        $expected = new Request([
            'method'              => 'get',
            'url'                 => $this->apiUrl . '/products',
            'curlOptions'         => $this->options,
            'expectedStatusCodes' => [200, 203, 206, 404]
        ]);

        $this->assertEquals($expected, $this->createMysqlToRequest()->transform($query));
    }

    #[Test]
    #[Group('unit')]
    public function selectJoined() {
        $query    = 'SELECT p.name FROM products p JOIN product.categories c ON c.id = p.categories_id';
        $expected = new Request([
            'method'              => 'get',
            'url'                 => $this->apiUrl . '/products',
            'curlOptions'         => $this->options,
            'expectedStatusCodes' => [200, 203, 206, 404]
        ]);

        $this->assertEquals($expected, $this->createMysqlToRequest()->transform($query));
    }

    #[Test]
    #[Group('unit')]
    public function insert() {
        $query    = 'INSERT INTO products (name) VALUES ("myName")';
        $expected = new Request([
            'method'             => 'post',
            'url'                => $this->apiUrl . '/products',
            'curlOptions'        => $this->options,
            'payload'            => json_encode(['name' => 'myName']),
            'expectedStatusCodes'=> [200, 201, 202, 203, 204, 205]
        ]);

        $this->assertEquals($expected, $this->createMysqlToRequest()->transform($query));
    }

    #[Test]
    #[Group('unit')]
    public function update() {
        $query    = 'UPDATE products SET name="myValue" WHERE id=1';
        $expected = new Request([
            'method'              => 'put',
            'url'                 => $this->apiUrl . '/products/1',
            'curlOptions'         => $this->options,
            'payload'             => json_encode(['name' => 'myValue']),
            'expectedStatusCodes' => [200, 202, 203, 204, 205, 404]
        ]);

        $this->assertEquals($expected, $this->createMysqlToRequest()->transform($query));
    }

    #[Test]
    #[Group('unit')]
    public function updateAll() {
        $query    = 'UPDATE products SET name="myValue"';
        $expected = new Request([
            'method'              => 'put',
            'url'                 => $this->apiUrl . '/products',
            'curlOptions'         => $this->options,
            'payload'             => json_encode(['name' => 'myValue']),
            'expectedStatusCodes' => [200, 202, 203, 204, 205, 404]
        ]);

        $this->assertEquals($expected, $this->createMysqlToRequest()->transform($query));
    }

    #[Test]
    #[Group('unit')]
    public function updatePatch() {
        $query    = 'UPDATE products SET name="myValue" WHERE id=1';
        $expected = new Request([
            'method'              => 'patch',
            'url'                 => $this->apiUrl . '/products/1',
            'curlOptions'         => $this->options,
            'payload'             => json_encode(['name' => 'myValue']),
            'expectedStatusCodes' => [200, 202, 203, 204, 205, 404]
        ]);

        $optionsOverride = [
            'driverOptions' => [
                'use_patch' => true,
            ],
        ];

        $this->assertEquals($expected, $this->createMysqlToRequest($optionsOverride)->transform($query));
    }

    #[Test]
    #[Group('unit')]
    public function delete() {
        $query    = 'DELETE FROM products WHERE id=1';
        $expected = new Request([
            'method'              => 'delete',
            'url'                 => $this->apiUrl . '/products/1',
            'curlOptions'         => $this->options,
            'expectedStatusCodes' => [200, 202, 203, 204, 205, 404]
        ]);

        $this->assertEquals($expected, $this->createMysqlToRequest()->transform($query));
    }

    #[Test]
    #[Group('unit')]
    public function brokenQuery() {
        $query = 'SHIT products WHERE dirt=1';
        $this->expectException(\Exception::class);
        $this->createMysqlToRequest()->transform($query);
    }
}
