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

use Circle\DoctrineRestDriver\Types\Identifier;
use Doctrine\ORM\Mapping\ClassMetadata;
use PHPSQLParser\PHPSQLParser;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;

/**
 * Tests the identifier type
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 * @coversDefaultClass Circle\DoctrineRestDriver\Types\Identifier
 */
#[CoversClass(Identifier::class)]
#[CoversMethod(Identifier::class,'create')]
#[CoversMethod(Identifier::class,'alias')]
#[CoversMethod(Identifier::class,'column')]
class IdentifierTest extends \PHPUnit\Framework\TestCase {

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function create() {
        $parser = new PHPSQLParser();
        $tokens = $parser->parse('SELECT name FROM products WHERE id=1');

        $this->assertSame('1', Identifier::create($tokens));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function createWithStringId() {
        $parser = new PHPSQLParser();
        $tokens = $parser->parse('SELECT name FROM products WHERE id="test"');

        $this->assertSame('test', Identifier::create($tokens));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function createWithStringIdSingleQuotes() {
        $parser = new PHPSQLParser();
        $tokens = $parser->parse('SELECT name FROM products WHERE id=\'test\'');

        $this->assertSame('test', Identifier::create($tokens));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function createWithStringIdNoQuotes() {
        $parser = new PHPSQLParser();
        $tokens = $parser->parse('SELECT name FROM products WHERE id=test');

        $this->assertSame('test', Identifier::create($tokens));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function createWithEmptyId() {
        $parser = new PHPSQLParser();
        $tokens = $parser->parse('SELECT name FROM products WHERE name="test"');

        $this->assertSame('', Identifier::create($tokens));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function alias() {
        $parser = new PHPSQLParser();
        $tokens = $parser->parse('SELECT name FROM products WHERE id=1');

        $this->assertSame('id', Identifier::alias($tokens));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function column() {
        $parser = new PHPSQLParser();
        $tokens = $parser->parse('SELECT name FROM products WHERE id=1');

        $metaDataEntry = $this->getMockBuilder(ClassMetadata::class)->disableOriginalConstructor()->getMock();
        $metaDataEntry
            ->expects($this->once())
            ->method('getTableName')
            ->willReturn('products');
        $metaDataEntry
            ->expects($this->once())
            ->method('getIdentifierColumnNames')
            ->willReturn(['testId']);

        $metaData = $this->getMockBuilder('Circle\DoctrineRestDriver\MetaData')->disableOriginalConstructor()->getMock();
        $metaData
            ->expects($this->once())
            ->method('get')
            ->willReturn([$metaDataEntry]);

        $this->assertSame('testId', Identifier::column($tokens, $metaData));
    }
}
