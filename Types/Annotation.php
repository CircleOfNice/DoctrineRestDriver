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

namespace Circle\DoctrineRestDriver\Types;

use Circle\DoctrineRestDriver\Annotations\DataSource;
use Circle\DoctrineRestDriver\Annotations\RoutingTable;

/**
 * Extracts id information from a sql token array
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 */
class Annotation {

    /**
     * returns the corresponding data source annotation if exists
     *
     * @param  RoutingTable $annotations
     * @param  string       $entityAlias
     * @param  string       $method
     * @return DataSource|null
     */
    public static function get(RoutingTable $annotations, $entityAlias, $method) {

        // check if custom
        $debug = 1 ;

        if (!self::exists($annotations, $entityAlias, $method)) return null;

        return $annotations->get($entityAlias)->$method();
    }

    /**
     * checks if the annotation exists
     *
     * @param  RoutingTable $annotations
     * @param  string       $entityAlias
     * @param  string       $method
     * @return boolean
     */
    public static function exists(RoutingTable $annotations = null, $entityAlias, $method) {
        return !empty($annotations) && $annotations->get($entityAlias) !== null && $annotations->get($entityAlias)->$method() !== null;
    }
}
