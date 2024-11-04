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

use Circle\DoctrineRestDriver\Types\HttpHeader;
use PHPSQLParser\PHPSQLParser;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;

/**
 * Tests the http header
 *
 * @author    Djane Rey Mabelin <thedjaney@gmail.com>
 * @copyright 2016
 *
 */
#[CoversClass(HttpHeader::class)]
#[CoversMethod(HttpHeader::class,'create')]
class HttpHeaderTest extends \PHPUnit\Framework\TestCase {

    /**
     * @var array
     */
    private $options;

    /**
     * {@inheritdoc}
     */
    public function setUp() : void {
        $this->options = [
            'security_strategy'  => 'none',
            'CURLOPT_MAXREDIRS'  => 22,
            'CURLOPT_HTTPHEADER' => 'Content-Type: text/plain'
        ];
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function create() {
        $query  = 'SELECT name FROM products WHERE id=1';
        $parser = new PHPSQLParser();
        $token  = $parser->parse($query);
        $header = HttpHeader::create($this->options, $token);

        $expectedHeader = [
            'CURLOPT_HTTPHEADER' => ['Content-Type: text/plain']
        ];
        $this->assertEquals($expectedHeader, $header);
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function createWithPaginationIsDefault() {
        $query  = 'SELECT name FROM products LIMIT 5 OFFSET 2';
        $parser = new PHPSQLParser();
        $token  = $parser->parse($query);
        $header = HttpHeader::create($this->options, $token);

        $expectedHeader = [
            'CURLOPT_HTTPHEADER' => [
                'Content-Type: text/plain',
                'Limit: 5',
                'Offset: 2',
            ],
        ];
        $this->assertEquals($expectedHeader, $header);
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function createWithoutPagination() {
        $query  = 'SELECT name FROM products LIMIT 5 OFFSET 2';
        $parser = new PHPSQLParser();
        $token  = $parser->parse($query);
        $this->options['pagination_as_query'] = true;
        $header = HttpHeader::create($this->options, $token);

        $expectedHeader = [
            'CURLOPT_HTTPHEADER' => ['Content-Type: text/plain'],
        ];
        $this->assertEquals($expectedHeader, $header);
    }
}
