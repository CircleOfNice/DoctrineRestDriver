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

namespace Circle\DoctrineRestDriver\Transformers;

use Circle\DoctrineRestDriver\Annotations\RoutingTable;
use Circle\DoctrineRestDriver\Enums\HttpMethods;
use Circle\DoctrineRestDriver\Factory\RequestFactory;
use Circle\DoctrineRestDriver\Types\Annotation;
use Circle\DoctrineRestDriver\Types\Id;
use Circle\DoctrineRestDriver\Types\Request;
use Circle\DoctrineRestDriver\Types\SqlOperation;
use Circle\DoctrineRestDriver\Types\SqlQuery;
use Circle\DoctrineRestDriver\Types\Table;
use Circle\DoctrineRestDriver\Types\Url;
use Circle\DoctrineRestDriver\Validation\Assertions;
use PHPSQLParser\PHPSQLParser;

/**
 * Transforms a given sql query to a corresponding request
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 */
class MysqlToRequest {

    /**
     * @var PHPSQLParser
     */
    private $parser;

    /**
     * @var RequestFactory
     */
    private $requestFactory;

    /**
     * @var array
     */
    private $options;

    /**
     * @var RoutingTable
     */
    private $routings;

    /**
     * MysqlToRequest constructor
     *
     * @param array        $options
     * @param RoutingTable $routings
     */
    public function __construct(array $options, RoutingTable $routings) {
        $this->options        = $options;
        $this->parser         = new PHPSQLParser();
        $this->requestFactory = new RequestFactory();
        $this->routings       = $routings;
    }

    /**
     * Transforms the given query into a request object
     *
     * @param  string $query
     * @return Request
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function transform($query) {
        $usePatch = isset($this->options['driverOptions']['use_patch']) ? $this->options['driverOptions']['use_patch'] : false;

        $tokens     = $this->parser->parse($query);
        $method     = HttpMethods::ofSqlOperation(SqlOperation::create($tokens), $usePatch);
        // Customs Method

//        if ($tokens['SET'])
//            if (isset($tokens['SET'][0]))

        $customs = Annotation::get($this->routings, Table::create($tokens),'customs') ;
        $annotation = null ;

        // TODO : proprement.

        if ($customs) {
            foreach ($customs as $custom) {
                if (isset($tokens['SET'][0]['sub_tree'][2]['base_expr'])) {
                    $classTest = ($custom::$functionClass);
                    $classTest = new $classTest('');

                    if ($tokens['SET'][0]['sub_tree'][2]['base_expr'] == $classTest::$functionName) {
                        //                $annotation = Annotation::get($this->routings, Table::create($tokens), 'FLAG');
                        $annotation = Annotation::get($this->routings, Table::create($tokens), $custom::class);
                    }
                }
            }
        }


        if (!$annotation)
        $annotation = Annotation::get($this->routings, Table::create($tokens), $method);

        return $this->requestFactory->createOne($method, $tokens, $this->options, $annotation);
    }
}
