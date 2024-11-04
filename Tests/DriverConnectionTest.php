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


use Circle\DoctrineRestDriver\Annotations\Routing;
use Circle\DoctrineRestDriver\Annotations\RoutingTable;
use Circle\DoctrineRestDriver\Driver;
use Circle\DoctrineRestDriver\DriverConnection;
use Circle\DoctrineRestDriver\Statement;
use Circle\DoctrineRestDriver\Types\Result;
use Doctrine\DBAL\Driver\Exception;
use Doctrine\DBAL\Platforms\MySQLPlatform;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Tests the driver Connection
 *
 * @author    Nurdin David <david.nurdin@respawnsive.com>
 *
 */
#[CoversClass(DriverConnection::class)]
#[CoversMethod(DriverConnection::class,'__construct')]
#[CoversMethod(DriverConnection::class,'getServerVersion')]
#[CoversMethod(DriverConnection::class,'rollBack')]
#[CoversMethod(DriverConnection::class,'commit')]
#[CoversMethod(DriverConnection::class,'beginTransaction')]
#[CoversMethod(DriverConnection::class,'exec')]
#[CoversMethod(DriverConnection::class,'quote')]
#[CoversMethod(DriverConnection::class,'connect')]
#[CoversMethod(DriverConnection::class,'getNativeConnection')]
#[CoversMethod(DriverConnection::class,'prepare')]
#[CoversMethod(DriverConnection::class,'lastInsertId')]
#[CoversMethod(DriverConnection::class,'query')]
class DriverConnectionTest extends TestCase {

    /**
     * @var DriverConnection
     */
    private $driverConnection;

    /**
     * {@inheritdoc}
     */
    public function setUp(): void
    {
        $entities = [
            'products'       => 'Circle\DoctrineRestDriver\Tests\Entity\TestEntity',
        ];

        $routingTable = new RoutingTable($entities);
        $this->driverConnection = new DriverConnection(['host' => 'http://127.0.0.1:3000/app_dev.php/mockapi', 'driverOptions' => [
//            'authenticator_class' => 'HttpAuthentication',
            'CURLOPT_MAXREDIRS' => 25, 'CURLOPT_HTTPHEADER' => 'Content-Type: application/json'] ], new Driver(), $routingTable);
    }

    #[Test]
    #[Group('unit')]
    public function getServerVersion() {
        $this->assertIsString("X", $this->driverConnection->getServerVersion());
    }

    #[Test]
    #[Group('unit')]
    public function rollback() {
        $this->assertIsBool(true, $this->driverConnection->rollBack());
    }

    #[Test]
    #[Group('unit')]
    public function commit() {
        $this->assertIsBool(true, $this->driverConnection->commit());
    }

    #[Test]
    #[Group('unit')]
    public function beginTransaction() {
        $this->assertIsBool(true, $this->driverConnection->beginTransaction());
    }

    #[Test]
    #[Group('unit')]
    public function exec() {
        $this->assertIsInt(1, $this->driverConnection->exec(''));
    }

    #[Test]
    #[Group('unit')]
    public function quote() {
        $this->assertIsString('',$this->driverConnection->quote(''));
    }

    #[Test]
    #[Group('unit')]
    public function connect() {
        $this->assertIsBool(true,$this->driverConnection->connect());
    }

    #[Test]
    #[Group('unit')]
    public function getNativeConnection() {
        $this->assertInstanceOf(DriverConnection::class, $this->driverConnection->getNativeConnection());
    }

    #[Test]
    #[Group('unit')]
    public function prepare() {
        $this->assertInstanceOf(Statement::class, $this->driverConnection->prepare(''));
    }


    /**
     * @throws Exception
     */
    #[Test]
    #[Group('unit')]
    public function lastInsertId() {
        $this->driverConnection->prepare('INSERT INTO products (`name`,`value`) VALUES (\'test_name\',\'test_value\')')->execute();
        $this->assertIsInt(1, $this->driverConnection->lastInsertId());
    }

    #[Test]
    #[Group('unit')]
    public function lastInsertIdFail() {
        $this->driverConnection->prepare('SELECT name FROM products WHERE id = 1')->execute();
        $this->assertIsInt(1, $this->driverConnection->lastInsertId());
    }

    #[Test]
    #[Group('unit')]
    public function query() {
        $this->assertInstanceOf(Result::class, $this->driverConnection->query('SELECT name FROM products WHERE id = 1'));
    }

}
