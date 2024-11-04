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

use Circle\DoctrineRestDriver\Annotations\Reader;
use Circle\DoctrineRestDriver\Annotations\Select;
use Circle\DoctrineRestDriver\Tests\Entity\TestEntity;
use Doctrine\Common\Annotations\AnnotationRegistry;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;
use ReflectionClass;

/**
 * Tests the annotation reader
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 */
#[CoversClass(Reader::class)]
#[CoversMethod(Reader::class, '__construct')]
#[CoversMethod(Reader::class, 'read')]
class ReaderTest extends \PHPUnit\Framework\TestCase {

    /**
     * {@inheritdoc}
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function setUp(): void
    {

    }

    #[Test]
    #[Group('unit')]
    public function getRoute() {
        $reader   = new Reader();
        $class    = new ReflectionClass(TestEntity::class);
        $expected = new Select([
            'value' => 'http://127.0.0.1:3000/app_dev.php/mockapi/products'
        ]);

        $actual = $reader->read($class, Select::class) ;
        $this->assertEquals($expected, $actual);
    }
}
