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

use Circle\DoctrineRestDriver\Types\Value;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;

/**
 * Tests the value type
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 */
#[CoveredClass(Value::class)]
#[CoversMethod(Value::class,'create')]
class ValueTest extends \PHPUnit\Framework\TestCase {

    /**
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    #[Test]
    #[Group('unit')]
    public function create() {
        $this->assertSame(1, Value::create('1'));
        $this->assertSame(1.01, Value::create('1.01'));
        $this->assertSame('hello', Value::create('hello'));
        $this->assertSame('hello', Value::create('"hello"'));
        $this->assertSame('hello', Value::create('\'hello\''));
        $this->assertSame('hello', Value::create('`hello`'));
        $this->assertSame('\'hello"', Value::create('\'hello"'));

        $encoded = '{"test":true}';

        $this->assertSame($encoded, Value::create("\"{$encoded}\""));
        $this->assertSame($encoded, Value::create("{$encoded}"));

        $this->assertSame(true, Value::create('true'));
        $this->assertSame(false, Value::create('false'));
        $this->assertSame(null, Value::create('null'));

        $this->assertNotSame(null, Value::create('false'));
    }
}
