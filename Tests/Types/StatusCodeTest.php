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

use Circle\DoctrineRestDriver\Enums\HttpMethods;
use Circle\DoctrineRestDriver\Types\StatusCode;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;

/**
 * Tests the status code type
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 */
#[CoversClass(StatusCode::class)]
#[CoversMethod(StatusCode::class,'create')]

class StatusCodeTest extends \PHPUnit\Framework\TestCase {

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function create() {
        $annotation = $this->getMockBuilder('Circle\DoctrineRestDriver\Annotations\DataSource')->getMock();
        $annotation
            ->expects($this->exactly(2))
            ->method('getStatusCodes')
            ->willReturn([202]);

        $this->assertContains(202, StatusCode::create(HttpMethods::POST, $annotation));
    }

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function createWithEmptyStatusCode() {
        $annotation = $this->getMockBuilder('Circle\DoctrineRestDriver\Annotations\DataSource')->getMock();
        $annotation
            ->expects($this->once())
            ->method('getStatusCodes')
            ->willReturn(null);

        $this->assertContains(201, StatusCode::create(HttpMethods::POST, $annotation));
    }
}
