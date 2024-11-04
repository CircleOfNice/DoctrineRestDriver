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

use Circle\DoctrineRestDriver\Annotations\Delete;
use Circle\DoctrineRestDriver\Annotations\Select;
use Circle\DoctrineRestDriver\Annotations\Fetch;
use Circle\DoctrineRestDriver\Annotations\Insert;
use Circle\DoctrineRestDriver\Annotations\Update;
use Circle\DoctrineRestDriver\Annotations\Routing;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;

/**
 * Tests the routing bag
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 */
#[CoversClass(Routing::class)]
#[CoversMethod(Routing::class, '__construct')]
#[CoversMethod(Routing::class, 'post')]
#[CoversMethod(Routing::class, 'put')]
#[CoversMethod(Routing::class, 'patch')]
#[CoversMethod(Routing::class, 'get')]
#[CoversMethod(Routing::class, 'delete')]
#[CoversMethod(Routing::class, 'getAll')]
class RoutingTest extends \PHPUnit\Framework\TestCase {

    public Routing $routing;

    /**
     * {@inheritdoc}
     */
    public function setUp(): void
    {
        $this->routing = new Routing('Circle\DoctrineRestDriver\Tests\Entity\AssociatedEntity');
    }

    #[Test]
    #[Group('unit')]
    public function post() {
        $this->assertSame(null, $this->routing->post());
    }

    #[Test]
    #[Group('unit')]
    public function put() {
        $this->assertSame(null, $this->routing->put());
    }

    #[Test]
    #[Group('unit')]
    public function patch() {
        $this->assertSame(null, $this->routing->patch());
    }

    #[Test]
    #[Group('unit')]
    public function get() {
        $this->assertSame(null, $this->routing->get());
    }
    #[Test]
    #[Group('unit')]
    public function delete() {
        $this->assertSame(null, $this->routing->delete());
    }
    #[Test]
    #[Group('unit')]
    public function getAll() {
        $this->assertSame(null, $this->routing->getAll());
    }
}
