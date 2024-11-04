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

use Circle\DoctrineRestDriver\Exceptions\DoctrineRestDriverException;
use Circle\DoctrineRestDriver\Statement;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;

/**
 * Tests the statement
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 */
#[CoversClass(Statement::class)]
#[CoversMethod(Statement::class,'bindParam')]
#[CoversMethod(Statement::class,'errorInfo')]
#[CoversMethod(Statement::class,'errorCode')]
#[CoversMethod(Statement::class,'columnCount')]
#[CoversMethod(Statement::class,'fetchColumn')]
#[CoversMethod(Statement::class,'getIterator')]
#[CoversMethod(Statement::class,'fetchAll')]
#[CoversMethod(Statement::class,'execute')]

#[CoversMethod(Statement::class,'rowCount')]
#[CoversMethod(Statement::class,'closeCursor')]

class StatementTest extends \PHPUnit\Framework\TestCase {

    /**
     * @var Statement
     */
    private $statement;
    private $statementFail;

    /**
     * {@inheritdoc}
     */
    public function setUp() : void {
        $routings = $this->getMockBuilder('Circle\DoctrineRestDriver\Annotations\RoutingTable')->disableOriginalConstructor()->getMock();
        $routings
            ->expects($this->any())
            ->method('get')
            ->willReturn(null);

        $params = [
            'host'          => 'http://www.circle.ai',
            'user'          => 'Aladdin',
            'password'      => 'OpenSesame',
            'driverOptions' => [
                'authenticator_class' => 'HttpAuthentication'
            ]
        ];
        $this->statement = new Statement('SELECT name FROM products WHERE id=1', $params, $routings);

        $paramsError = $params ;
        $paramsError['host'] = 'http://127.0.0.1:3000/app_dev.php/mockapi';
        $this->statementFail = new Statement('SELECT name FROM products WHERE id=500', $paramsError, $routings);
    }

    #[Test]
    #[Group('unit')]
    public function bindParam() {
        $test = 'test';
        $this->expectException(\Exception::class);
        $this->statement->bindParam('test', $test);
    }

    #[Test]
    #[Group('unit')]
    public function errorInfo() {
        $this->assertSame(null, $this->statement->errorInfo());
    }

    #[Test]
    #[Group('unit')]
    public function errorCode() {
        $this->assertSame(null, $this->statement->errorCode());
    }

    #[Test]
    #[Group('unit')]
    public function columnCount() {
        $this->assertSame(0, $this->statement->columnCount());
    }

    #[Test]
    #[Group('unit')]
    public function fetchColumn() {
        $this->expectException(\Exception::class);
        $this->statement->fetchColumn(1);
    }

    #[Test]
    #[Group('unit')]
    public function getIterator() {
        $this->assertSame('SELECT name FROM products WHERE id=1', $this->statement->getIterator());
    }

    #[Test]
    #[Group('unit')]
    public function fetchAllFalseMode() {
        $this->expectException(\Exception::class);
        $this->statement->fetchAll(\PDO::FETCH_CLASS);
    }

    #[Test]
    #[Group('unit')]
    public function fetchAll() {
        $this->assertEquals([], $this->statement->fetchAll(\PDO::FETCH_ASSOC));
    }

    #[Test]
    #[Group('unit')]
    public function rowCount() {
        $this->statement->fetchAll(\PDO::FETCH_ASSOC) ;
        $this->assertIsInt(0, $this->statement->rowCount());
    }

    #[Test]
    #[Group('unit')]
    public function closeCursor() {
        $this->assertIsBool(true, $this->statement->closeCursor());
    }
    #[Test]
    #[Group('unit')]
    public function executeFail() {
        $this->expectException(DoctrineRestDriverException::class);
        $this->statementFail->execute();
    }


}
