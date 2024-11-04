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

use Circle\DoctrineRestDriver\Annotations\RoutingTable;
use Circle\DoctrineRestDriver\Annotations\Select;
use Circle\DoctrineRestDriver\Types\Annotation;
use PHPSQLParser\PHPSQLParser;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;

/**
 * Tests the annotation type
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 */
#[CoversClass(Annotation::class)]
#[CoversMethod(Annotation::class,'exists')]
#[CoversMethod(Annotation::class,'get')]
class AnnotationTest extends \PHPUnit\Framework\TestCase {

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function exists() {
        $routings = new RoutingTable(['products' => 'Circle\DoctrineRestDriver\Tests\Entity\TestEntity']);

        $this->assertTrue(Annotation::exists($routings, 'products', 'get'));
        $this->assertFalse(Annotation::exists($routings, 'products', 'post'));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function get() {
        $routings   = new RoutingTable(['products' => 'Circle\DoctrineRestDriver\Tests\Entity\TestEntity']);
        $annotation = new Select([
            'value' => 'http://127.0.0.1:3000/app_dev.php/mockapi/products'
        ]);

        $this->assertEquals($annotation, Annotation::get($routings, 'products', 'get'));
    }
}
