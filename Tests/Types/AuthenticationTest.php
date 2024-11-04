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

use Circle\DoctrineRestDriver\Types\Authentication;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;

/**
 * Tests the authentication type
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 */
#[CoversClass(Authentication::class)]
#[CoversMethod(Authentication::class, 'create')]
#[CoversMethod(Authentication::class, 'assert')]
class AuthenticationTest extends \PHPUnit\Framework\TestCase {

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function create() {
        $this->assertInstanceOf('Circle\DoctrineRestDriver\Security\AuthStrategy', Authentication::create([]));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function createWithOptions() {
        $this->assertInstanceOf('Circle\DoctrineRestDriver\Security\HttpAuthentication', Authentication::create(['driverOptions' => ['authenticator_class' => 'HttpAuthentication']]));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function assert() {
        $authStrategy = $this->getMockBuilder('Circle\DoctrineRestDriver\Security\HttpAuthentication')->disableOriginalConstructor()->getMock();
        $this->assertSame($authStrategy, Authentication::assert($authStrategy));
    }
}
