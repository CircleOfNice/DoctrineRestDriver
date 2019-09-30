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

use Circle\DoctrineRestDriver\Types\HttpQuery;
use PHPSQLParser\PHPSQLParser;

/**
 * Tests the http query type
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 * @coversDefaultClass Circle\DoctrineRestDriver\Types\HttpQuery
 */
class HttpQueryTest extends \PHPUnit\Framework\TestCase {

    /**
     * @test
     * @group  unit
     * @covers ::create
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function create() {
        $parser   = new PHPSQLParser();
        $tokens   = $parser->parse('SELECT name FROM products t0 WHERE t0.id=1 AND t0.value="x=1" AND t0.name="test, name" OR (1=2 AND foo="bar")');
        $expected = 'value=x=1&name=test, name|(1=2 & foo=bar)';

        $this->assertSame($expected, HttpQuery::create($tokens));
    }
    
    /**
     * @test
     * @group unit
     * @covers ::create
     * 
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function createWithoutPaginationIsDefault() {
        $parser   = new PHPSQLParser();
        $tokens   = $parser->parse('SELECT name FROM products WHERE foo="bar" LIMIT 5 OFFSET 15');
        $expected = 'foo=bar';

        $this->assertSame($expected, HttpQuery::create($tokens));
    }
    
    /**
     * @test
     * @group unit
     * @covers ::create
     * 
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function createWithPagination() {
        $options = [
            'pagination_as_query' => true,
        ];
        $parser   = new PHPSQLParser();
        $tokens   = $parser->parse('SELECT name FROM products WHERE `foo`="bar" LIMIT 5 OFFSET 10');
        $expected = 'foo=bar&per_page=5&page=3';

        $this->assertSame($expected, HttpQuery::create($tokens, $options));
    }
    
    /**
     * @test
     * @group unit
     * @covers ::create
     * 
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function createWithCustomPagination() {
        $options = [
            'pagination_as_query' => true,
            'per_page_param'      => 'newkey_per_page',
            'page_param'          => 'newkey_page',
        ];
        $parser   = new PHPSQLParser();
        $tokens   = $parser->parse('SELECT `name` FROM products WHERE foo="bar" LIMIT 5 OFFSET 10');
        $expected = 'foo=bar&newkey_per_page=5&newkey_page=3';

        $this->assertSame($expected, HttpQuery::create($tokens, $options));
    }
}
