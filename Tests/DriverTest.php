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

namespace Circle\DoctrineRestDriver\Tests;

use Doctrine\DBAL\Driver\API\ExceptionConverter;
use Circle\DoctrineRestDriver\DriverConnection;
use Doctrine\DBAL\Connection as AbstractConnection;
use Circle\DoctrineRestDriver\Connection;
use Circle\DoctrineRestDriver\Driver;
use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Platforms\MySQLPlatform;
use Doctrine\DBAL\Schema\MySQLSchemaManager ;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Tests the driver
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 */
#[CoversClass(Driver::class)]
#[CoversMethod(Driver::class,'getDatabasePlatform')]
#[CoversMethod(Driver::class,'getSchemaManager')]
#[CoversMethod(Driver::class,'getName')]
#[CoversMethod(Driver::class,'getDatabase')]
#[CoversMethod(Driver::class,'connect')]
class DriverTest extends TestCase {

    /**
     * @var Driver
     */
    private $driver;

    /**
     * {@inheritdoc}
     */
    public function setUp(): void
    {
        $this->driver = new Driver();
    }

    #[Test]
    #[Group('unit')]
    public function getDatabasePlatform() {
        $this->assertInstanceOf(MySQLPlatform::class, $this->driver->getDatabasePlatform());
    }

    #[Test]
    #[Group('unit')]
    public function getSchemaManager() {
        $connection = $this->getMockBuilder(Connection::class)->disableOriginalConstructor()->getMock() ;
        $platform = $this->getMockBuilder(AbstractPlatform::class)->disableOriginalConstructor()->getMock();
        $actual =  $this->driver->getSchemaManager($connection,$platform) ;
        $this->assertInstanceOf(MySQLSchemaManager::class,$actual);
    }

    #[Test]
    #[Group('unit')]
    public function getNameTest() {
        $this->assertSame('circle_rest', $this->driver->getName());
    }

    #[Test]
    #[Group('unit')]
    public function getExceptionConverter() {
        $this->assertInstanceOf(ExceptionConverter::class, $this->driver->getExceptionConverter());
    }


    #[Test]
    #[Group('unit')]
    public function getDatabase() {
        $connection = $this->getMockBuilder(Connection::class)->disableOriginalConstructor()->getMock() ;
        $this->assertSame('rest_database', $this->driver->getDatabase($connection));
    }

    #[Test]
    #[Group('unit')]
    public function connect() {
        $params = [
            'driverClass'   => 'Circle\DoctrineRestDriver\Driver',
            'driverOptions' => [
                'security_strategy' => 'none'
            ],
            'user'     => 'user',
            'password' => 'password',
            'host'     => 'localhost'
        ];
        $connection = $this->driver->connect($params, null, null, $params['driverOptions']);
        $this->assertInstanceOf(DriverConnection::class, $connection);
    }
}
