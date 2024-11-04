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

namespace Circle\DoctrineRestDriver;

use Circle\DoctrineRestDriver\Annotations\RoutingTable;
use Doctrine\Common\EventManager;
use Doctrine\DBAL\Configuration;
use Doctrine\DBAL\Driver\ServerInfoAwareConnection;
use Doctrine\DBAL\ParameterType;
use Doctrine\DBAL\Driver\Statement as StatementInterface ;
use Doctrine\DBAL\Driver\Result as ResultInterface ;

class DriverConnection implements \Doctrine\DBAL\Driver\Connection,ServerInfoAwareConnection
{

    private $defaultFetchMode = \PDO::FETCH_ASSOC; // default fetch mode
    protected Statement $statement ;
    public ?EventManager $eventManager;
    public ?Configuration $config;
    public RoutingTable $routings;
    public array $params ;
    public Driver $driver ;

    public function __construct(array $params, Driver $driver, RoutingTable $routings, Configuration $config = null, EventManager $eventManager = null)
    {
        $this->routings = $routings;
        $this->params = $params ;
        $this->driver = $driver ;
        $this->config = $config ;
        $this->eventManager = $eventManager ;
    }
    public function getNativeConnection()
    {
        return $this ;
    }

    public function connect()
    {
        return true ;
    }

    /**
     * @throws \Exception
     */
    public function prepare($statement): StatementInterface
    {
        $this->connect();
        $this->statement = new Statement($statement, $this->params, $this->routings);
        $this->statement->setFetchMode($this->defaultFetchMode);

        return $this->statement;
    }
    /**
     * returns the last inserted id
     *
     * @param  string|null $seqName
     * @return int
     *
     * @SuppressWarnings("PHPMD.UnusedFormalParameter")
     */
    public function lastInsertId($seqName = null): int|false
    {
        if ($this->statement->getId() === null)
            return false ;

        return $this->statement->getId();
    }

    /**
     * Executes a query, returns a statement
     *
     * @param string $sql
     */
    public function query(string $sql): ResultInterface
    {
        $statement = $this->prepare(func_get_args()[0]);
        return $statement->execute();
    }
    public function quote($value, $type = ParameterType::STRING)
    {
        // TODO: Implement quote() method.
        return '' ;
    }

    public function exec(string $sql): int
    {
        // TODO: Implement exec() method.
        return 1 ;
    }

    public function beginTransaction()
    {
        return true;
    }

    public function commit()
    {
        return true;
    }

    public function rollBack()
    {
        return true;
    }

    public function getServerVersion()
    {
        return "X" ;
    }

}
