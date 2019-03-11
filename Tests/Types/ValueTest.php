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

/**
 * Tests the value type
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 * @coversDefaultClass Circle\DoctrineRestDriver\Types\Value
 */
class ValueTest extends \PHPUnit\Framework\TestCase {

    /**
     * @test
     * @group  unit
     * @covers ::create
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function create() {
        $this->assertSame(1, Value::create('1'));
        $this->assertSame(1.01, Value::create('1.01'));
        $this->assertSame('00', Value::create('00'));
        $this->assertSame('hello', Value::create('hello'));
        $this->assertSame('hello', Value::create('"hello"'));
        $this->assertSame('hello', Value::create('\'hello\''));
        $this->assertSame('hello', Value::create('`hello`'));
        $this->assertSame('\'hello"', Value::create('\'hello"'));
        $this->assertSame('\'hel\'lo\'', Value::create('\'\'hel\'\'lo\'\''));

        $this->assertSame("h\ne\nl\nl\no", Value::create("'h\ne\nl\nl\no'"));
        $this->assertNotSame("h\ne\nl\nl\no", Value::create("'h\ne\nl\nl\no'\n"));

        // any character outside of the quotes skips the "de-quoting"
        $this->assertSame("'hello'\n", Value::create("'hello'\n"));

        $encoded = '{"test":true}';

        $this->assertSame($encoded, Value::create("\"{$encoded}\""));
        $this->assertSame($encoded, Value::create("{$encoded}"));

        $this->assertSame(true, Value::create('true'));
        $this->assertSame(false, Value::create('false'));
        $this->assertSame(null, Value::create('null'));

        $this->assertNotSame(null, Value::create('false'));
    }

    /**
     * @test
     * @group  unit
     * @covers ::unquote
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function unquote() {
        $this->assertSame('\'foo\'bar"', Value::unquote('\'foo\'\'bar"'));
    }
}
