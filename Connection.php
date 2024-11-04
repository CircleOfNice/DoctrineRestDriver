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
use Doctrine\DBAL\Connection as AbstractConnection;
use Doctrine\DBAL\ParameterType;
use Doctrine\DBAL\Driver\ServerInfoAwareConnection;
use Doctrine\DBAL\Schema\LegacySchemaManagerFactory;


/**
 * Doctrine connection for the rest driver
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 * @method object getNativeConnection()
 */
class Connection extends \Doctrine\DBAL\Connection
{

    public RoutingTable $routings;
    public array $params ;
    public Driver $driver ;
    public ?Configuration $config ;
    public ?EventManager $eventManager ;

//
    public function __construct(array $params, Driver $driver, RoutingTable $routings, Configuration $config = null, EventManager $eventManager = null) {
        $this->routings = $routings;
        $this->params = $params ;
        $this->driver = $driver ;
        $config       ??= new Configuration();
        $config->setSchemaManagerFactory(new LegacySchemaManagerFactory()) ;
        $this->config = $config ;
        $this->_conn = new DriverConnection($params,$driver,$routings,$config,$eventManager) ;
        parent::__construct($params, $driver, $config, $eventManager);
    }

    // doesnt work on warning deprecated
//    public function createSchemaManager(): \Doctrine\DBAL\Schema\AbstractSchemaManager
//    {
//        $schemaManagerFactory = new LegacySchemaManagerFactory();
//        $this->schemaManagerFactory = $schemaManagerFactory;
//        return $schemaManagerFactory ;
//    }
////
//    /**
//     * prepares the statement execution
//     *
//     * @param  string $statement
//     * @return \Doctrine\DBAL\Driver\Statement
//     */
//    public function prepare($statement): \Doctrine\DBAL\Driver\Statement
//    {
////        $this->connect();
//
//        $this->statement = new Statement($statement, $this->params, $this->routings);
//        $this->statement->setFetchMode($this->defaultFetchMode);
//
//        return $this->statement;
//    }
//
//    /**
//     * returns the last inserted id
//     *
//     * @param  string|null $seqName
//     * @return int
//     *
//     * @SuppressWarnings("PHPMD.UnusedFormalParameter")
//     */
//    public function lastInsertId($seqName = null) {
//        return $this->statement->getId();
//    }
//
//    /**
//     * Executes a query, returns a statement
//     *
//     * @param string $sql
//     * @return \Doctrine\DBAL\Driver\Result
//     */
//    public function query(string $sql): \Doctrine\DBAL\Driver\Result
//    {
//        $statement = $this->prepare(func_get_args()[0]);
//        $statement->execute();
//
//        return $statement;
//    }
//
//    public function quote($value, $type = ParameterType::STRING)
//    {
//        // TODO: Implement quote() method.
//    }
//
//    public function exec(string $sql): int
//    {
//        // TODO: Implement exec() method.
//    }
//
//    public function beginTransaction()
//    {
//        // TODO: Implement beginTransaction() method.
//    }
//
//    public function commit()
//    {
//        // TODO: Implement commit() method.
//    }
//
//    public function rollBack()
//    {
//        // TODO: Implement rollBack() method.
//    }
//
//    public function getServerVersion()
//    {
//        // TODO: Implement getServerVersion() method.
//    }
}
