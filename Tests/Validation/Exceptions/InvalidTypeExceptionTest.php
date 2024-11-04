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

namespace Circle\DoctrineRestDriver\Tests\Validation\Exceptions;

use Circle\DoctrineRestDriver\Validation\Exceptions\InvalidTypeException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;

/**
 * Tests the invalid type exception
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 *
 * @SuppressWarnings("PHPMD.StaticAccess")
 */
#[CoversClass(InvalidTypeException::class)]
#[CoversMethod(InvalidTypeException::class,'__construct')]
class InvalidTypeExceptionTest extends \PHPUnit\Framework\TestCase {

    #[Test]
    #[Group('unit')]
    public function construct() {
        $exception = new InvalidTypeException('string', 'someKey', 'someValue');
        $this->assertSame('The given value someValue for "someKey" is not of type string', $exception->getMessage());
    }
}
