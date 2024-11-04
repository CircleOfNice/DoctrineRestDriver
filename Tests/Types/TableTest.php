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

use Circle\DoctrineRestDriver\Annotations\Delete;
use Circle\DoctrineRestDriver\Annotations\Select;
use Circle\DoctrineRestDriver\Annotations\Fetch;
use Circle\DoctrineRestDriver\Annotations\Insert;
use Circle\DoctrineRestDriver\Annotations\Update;
use Circle\DoctrineRestDriver\Annotations\Routing;
use Circle\DoctrineRestDriver\Annotations\RoutingTable;
use Circle\DoctrineRestDriver\Types\Table;
use PHPSQLParser\PHPSQLParser;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;

/**
 * Tests the table type
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 *
 * @SuppressWarnings("PHPMD.TooManyPublicMethods")
 */
#[CoversClass(Table::class)]
#[CoversMethod(Table::class,'create')]
#[CoversMethod(Table::class,'alias')]
#[CoversMethod(Table::class,'replace')]
class TableTest extends \PHPUnit\Framework\TestCase {

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function createSelect() {
        $parser = new PHPSQLParser();
        $tokens = $parser->parse('SELECT name FROM products p0');

        $this->assertSame('products', Table::create($tokens));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function aliasSelect() {
        $parser = new PHPSQLParser();
        $tokens = $parser->parse('SELECT name FROM products p0');

        $this->assertSame('p0', Table::alias($tokens));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function createSelectWithUrl() {
        $parser = new PHPSQLParser();
        $tokens = $parser->parse('SELECT name FROM "http://www.circle.ai/api" p0');

        $this->assertSame('http://www.circle.ai/api', Table::create($tokens));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function aliasSelectWithUrl() {
        $parser = new PHPSQLParser();
        $tokens = $parser->parse('SELECT name FROM "http://www.circle.ai/api" p0');

        $this->assertSame('p0', Table::alias($tokens));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function createInsert() {
        $parser = new PHPSQLParser();
        $tokens = $parser->parse('INSERT INTO products (name) VALUES (name)');

        $this->assertSame('products', Table::create($tokens));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function aliasInsert() {
        $parser = new PHPSQLParser();
        $tokens = $parser->parse('INSERT INTO products (name) VALUES (name)');

        $this->assertSame(null, Table::alias($tokens));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function createInsertWithUrl() {
        $parser = new PHPSQLParser();
        $tokens = $parser->parse('INSERT INTO "http://www.circle.ai/api" (name) VALUES (name)');

        $this->assertSame('http://www.circle.ai/api', Table::create($tokens));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function aliasInsertWithUrl() {
        $parser = new PHPSQLParser();
        $tokens = $parser->parse('INSERT INTO "http://www.circle.ai/api" (name) VALUES (name)');

        $this->assertSame(null, Table::alias($tokens));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function createUpdate() {
        $parser = new PHPSQLParser();
        $tokens = $parser->parse('UPDATE products p0 set name="name"');

        $this->assertSame('products', Table::create($tokens));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function aliasUpdate() {
        $parser = new PHPSQLParser();
        $tokens = $parser->parse('UPDATE products p0 set name="name"');

        $this->assertSame('p0', Table::alias($tokens));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function createUpdateWithUrl() {
        $parser = new PHPSQLParser();
        $tokens = $parser->parse('UPDATE "http://www.circle.ai/api" p0 set name="name"');

        $this->assertSame('http://www.circle.ai/api', Table::create($tokens));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function aliasUpdateWithUrl() {
        $parser = new PHPSQLParser();
        $tokens = $parser->parse('UPDATE "http://www.circle.ai/api" p0 set name="name"');

        $this->assertSame('p0', Table::alias($tokens));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function replace() {
        $parser = new PHPSQLParser();

        $tokens = $parser->parse('UPDATE products p0 set name="name"');
        $this->assertSame('http://www.circle.ai/put', Table::create(Table::replace($tokens, 'http://www.circle.ai/put')));

        $tokens = $parser->parse('INSERT INTO products (test) VALUES ("test")');
        $this->assertSame('http://www.circle.ai/post', Table::create(Table::replace($tokens, 'http://www.circle.ai/post')));

        $tokens = $parser->parse('SELECT * FROM products');
        $this->assertSame('http://www.circle.ai/get', Table::create(Table::replace($tokens, 'http://www.circle.ai/get')));
    }
}
