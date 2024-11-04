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

namespace Circle\DoctrineRestDriver\Tests\Annotations;

use Circle\DoctrineRestDriver\Annotations\Routing;
use Circle\DoctrineRestDriver\Annotations\RoutingTable;
use Doctrine\Common\Annotations\AnnotationRegistry;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;

/**
 * Tests the routing table
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 */
#[CoversClass(RoutingTable::class)]
#[CoversMethod(RoutingTable::class,'__construct')]
#[CoversMethod(RoutingTable::class,'get')]
//#[CoversMethod(RoutingTable::class,'<private>')]
class RoutingTableTest extends \PHPUnit\Framework\TestCase {

    /**
     * {@inheritdoc}
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function setUp(): void
    {
//        AnnotationRegistry::registerFile(__DIR__ . '/../../vendor/doctrine/orm/lib/Doctrine/ORM/Mapping/Entity.php');
//        AnnotationRegistry::registerFile(__DIR__ . '/../../vendor/doctrine/orm/lib/Doctrine/ORM/Mapping/Table.php');
//        AnnotationRegistry::registerFile(__DIR__ . '/../../vendor/doctrine/orm/lib/Doctrine/ORM/Mapping/Column.php');
//        AnnotationRegistry::registerFile(__DIR__ . '/../../vendor/doctrine/orm/lib/Doctrine/ORM/Mapping/Id.php');
//        AnnotationRegistry::registerFile(__DIR__ . '/../../vendor/doctrine/orm/lib/Doctrine/ORM/Mapping/GeneratedValue.php');
//        AnnotationRegistry::registerFile(__DIR__ . '/../../vendor/doctrine/orm/lib/Doctrine/ORM/Mapping/OneToMany.php');
//        AnnotationRegistry::registerFile(__DIR__ . '/../../vendor/doctrine/orm/lib/Doctrine/ORM/Mapping/ManyToOne.php');
//        AnnotationRegistry::registerFile(__DIR__ . '/../../Annotations/Insert.php');
//        AnnotationRegistry::registerFile(__DIR__ . '/../../Annotations/Update.php');
//        AnnotationRegistry::registerFile(__DIR__ . '/../../Annotations/Select.php');
//        AnnotationRegistry::registerFile(__DIR__ . '/../../Annotations/Delete.php');
//        AnnotationRegistry::registerFile(__DIR__ . '/../../Annotations/Fetch.php');
    }

    #[Test]
    #[Group('unit')]
    public function get() {
        $entities = [
            'categories'     => 'Circle\DoctrineRestDriver\Tests\Entity\AssociatedEntity',
            'nonImplemented' => 'Circle\DoctrineRestDriver\Tests\Entity\NonImplementedEntity',
            'products'       => 'Circle\DoctrineRestDriver\Tests\Entity\TestEntity',
        ];

        $routingTable = new RoutingTable($entities);
        $expected     = new Routing($entities['categories']);

        $this->assertEquals($expected, $routingTable->get('categories'));
    }
}
