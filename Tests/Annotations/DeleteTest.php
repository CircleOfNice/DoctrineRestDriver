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
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;

/**
 * Tests the delete annotation
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 */
#[CoversClass(Delete::class)]
#[Group('unit')]
class DeleteTest extends \PHPUnit\Framework\TestCase {

    #[Test]
    public function getRoute() {
        $delete = new Delete([
            'value'      => 'http://www.mySite.com/delete',
            'statusCodes' => [201],
            'method'     => 'DELETE',
            'options'    => []
        ]);

        $this->assertSame('http://www.mySite.com/delete', $delete->getRoute());
        $this->assertSame([201], $delete->getStatusCodes());
        $this->assertSame('DELETE', $delete->getMethod());
        $this->assertEquals([], $delete->getOptions());
    }
}
