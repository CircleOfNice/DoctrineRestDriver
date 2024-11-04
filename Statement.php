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
use Circle\DoctrineRestDriver\Exceptions\DoctrineRestDriverException;
use Circle\DoctrineRestDriver\Exceptions\Exceptions;
use Circle\DoctrineRestDriver\Exceptions\RequestFailedException;
use Circle\DoctrineRestDriver\Security\AuthStrategy;
use Circle\DoctrineRestDriver\Transformers\MysqlToRequest;
use Circle\DoctrineRestDriver\Types\Authentication;
use Circle\DoctrineRestDriver\Types\Result;
use Circle\DoctrineRestDriver\Types\SqlQuery;
use Circle\DoctrineRestDriver\Validation\Assertions;
use Doctrine\DBAL\Driver\Statement as StatementInterface;
use Doctrine\DBAL\Exception\ServerException;

//use Doctrine\DBAL\Driver\Result as ResultInterface ;
/**
 * Executes the statement - sends requests to an api
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 * @SuppressWarnings("PHPMD.TooManyPublicMethods")
 */
class Statement implements StatementInterface {

    /**
     * @var string
     */
    private $query;

    /**
     * @var MysqlToRequest
     */
    private $mysqlToRequest;

    /**
     * @var array
     */
    private $params = [];

    /**
     * @var RestClient
     */
    private $restClient;

    /**
     * @var array
     */
    private $result;

    /**
     * @var int
     */
    private $id;

    /**
     * @var int
     */
    private $errorCode;

    /**
     * @var string
     */
    private $errorMessage;

    /**
     * @var int
     */
    private $fetchMode;

    /**
     * @var AuthStrategy
     */
    private $authStrategy;

    /**
     * @var RoutingTable
     */
    private $routings;

    /**
     * @var array
     */
    private $options;

    /**
     * Statement constructor
     *
     * @param  string       $query
     * @param  array        $options
     * @param  RoutingTable $routings
     * @throws \Exception
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function __construct($query, array $options, RoutingTable $routings) {
        $this->query          = SqlQuery::quoteUrl($query);
        $this->routings       = $routings;
        $this->mysqlToRequest = new MysqlToRequest($options, $this->routings);
        $this->restClient     = new RestClient();

        $this->authStrategy = Authentication::create($options);
        $this->options      = $options;
    }

    public function getIterator()
    {
        return $this->query ;
    }
    /**
     * {@inheritdoc}
     */
    public function bindValue($param, $value, $type = null) {
        $this->params[$param] = $value;
        return true;
    }

    /**
     * {@inheritdoc}
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function bindParam($column, &$variable, $type = null, $length = null) {
        return Exceptions::MethodNotImplementedException(get_class($this), 'bindParam');
    }

    /**
     * {@inheritdoc}
     */
    public function errorCode() {
        return $this->errorCode;
    }

    /**
     * {@inheritdoc}
     */
    public function errorInfo() {
        return $this->errorMessage;
    }

    /**
     * {@inheritdoc}
     * @throws RequestFailedException
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function execute($params = null): Result
    {
        $query   = SqlQuery::setParams($this->query, $params !== null ? $params : $this->params);
        $tmp = $this->mysqlToRequest->transform($query) ;
        $request = $this->authStrategy->transformRequest($tmp);


//        dump($request->getUrlAndQuery());

        try {
            $response     = $this->restClient->send($request);
//            dump($response->getContent());

            if ($response->getStatusCode() == 401)
            {
                $debug = 1 ;

            }
            $result       = new Result($query, $request->getMethod(), $response, $this->options,$request);

            $this->result = $result->get();
            $this->id     = $result->id();

            return $result ;
        } catch(RequestFailedException|ServerException $e) {
            // as the error handling proposed by doctrine
            // does not work, we use the way of PDO_mysql
            // which just throws the possible errors
            throw new DoctrineRestDriverException($e->getMessage(), $e->getCode());
        }
    }

    /**
     * {@inheritdoc}
     */
    public function rowCount() {
        return count($this->result);
    }

    /**
     * {@inheritdoc}
     */
    public function closeCursor() {
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function columnCount() {
        return empty($this->result) ? 0 : count($this->result[0]);
    }

    /**
     * {@inheritdoc}
     */
    public function setFetchMode($fetchMode, $arg2 = null, $arg3 = null) {
        $this->fetchMode = $fetchMode;

        return true;
    }

    /**
     * {@inheritdoc}
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function fetch($fetchMode = NULL, $cursorOrientation = \PDO::FETCH_ORI_NEXT, $cursorOffset = 0) {
        $fetchMode = empty($fetchMode) ? $this->fetchMode : $fetchMode;
        Assertions::assertSupportedFetchMode($fetchMode);

        if ($this->result === null)
            $this->result = [] ;

        return count($this->result) === 0 ? false : array_pop($this->result);
    }

    /**
     * {@inheritdoc}
     */
    public function fetchAll($fetchMode = NULL, $fetchArgument = NULL, $ctorArgs = NULL) {
        $result    = [];
        $fetchMode = empty($fetchMode) ? $this->fetchMode : $fetchMode;

        while (($row = $this->fetch($fetchMode))) array_push($result, $row);

        if ($this->result === null)
            $this->result = [] ; // @codeCoverageIgnore

        return $result;
    }

    /**
     * {@inheritdoc}
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function fetchColumn($columnIndex = 0) {
        return Exceptions::MethodNotImplementedException(get_class($this), 'fetchColumn');
    }


//    /**
//     * {@inheritdoc}
//     */
//    public function getIterator() {
//        return $this->query;
//    }

    /**
     * Returns the last auto incremented id
     *
     * @return int
     */
    public function getId() {
        return $this->id;
    }
}
