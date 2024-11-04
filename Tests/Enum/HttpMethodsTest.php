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

namespace Circle\DoctrineRestDriver\Tests\Enums;

use Circle\DoctrineRestDriver\Enums\HttpMethods;
use Circle\DoctrineRestDriver\Enums\SqlOperations;
use Circle\DoctrineRestDriver\Exceptions\InvalidSqlOperationException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;

/**
 * Tests the http methods enum
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 */
#[CoversMethod(HttpMethods::class,'ofSqlOperation')]
class HttpMethodsTest extends \PHPUnit\Framework\TestCase {

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     * @throws InvalidSqlOperationException
     */
    #[Test]
    #[Group('unit')]
    public function ofSqlOperation() {
        $this->assertEquals(HttpMethods::GET, HttpMethods::ofSqlOperation(SqlOperations::SELECT));
        $this->assertEquals(HttpMethods::PUT, HttpMethods::ofSqlOperation(SqlOperations::UPDATE));
        $this->assertEquals(HttpMethods::DELETE, HttpMethods::ofSqlOperation(SqlOperations::DELETE));
        $this->assertEquals(HttpMethods::POST, HttpMethods::ofSqlOperation(SqlOperations::INSERT));
        $this->assertEquals(HttpMethods::PATCH, HttpMethods::ofSqlOperation(SqlOperations::UPDATE, true));

        $this->expectException(\Exception::class);
        HttpMethods::ofSqlOperation('invalid');

    }
}
