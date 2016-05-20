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

use Circle\DoctrineRestDriver\Types\Payload;
use Circle\DoctrineRestDriver\Types\Routes;
use Doctrine\Common\Collections\ArrayCollection;
use PHPSQLParser\PHPSQLParser;

/**
 * Tests the routes type
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 * @coversDefaultClass Circle\DoctrineRestDriver\Types\Routes
 */
class RoutesTest extends \PHPUnit_Framework_TestCase {

    /**
     * @test
     * @group  unit
     * @covers ::create
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function create() {
        $options = [
            'routes' => __DIR__ . '/../app/config/rest_driver_routing.yml'
        ];

        $routes = [
            'products' => [
                'post' => 'products/create'
            ]
        ];

        $this->assertEquals(new ArrayCollection($routes), Routes::create($options));
    }
}