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

use Circle\DoctrineRestDriver\Enums\HttpMethods;
use Circle\DoctrineRestDriver\Validation\Assertions;

/**
 * Url type
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 */
class Url {

    /**
     * Returns an url depending on the given sql tokens
     *
     * @param  array  $tokens
     * @param  string $apiUrl
     * @param  array  $options
     * @return string
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public static function create(array $tokens, $apiUrl, array $options) {
        Assertions::assertHashMap('tokens', $tokens);
        Assertions::assertHashMap('options', $options);

        $routes = Routes::create($options);
        $method = HttpMethods::ofSqlOperation(SqlOperation::create($tokens));
        $table  = Table::create($tokens);
        $route  = !empty($routes->get($table)) && array_key_exists($method, $routes->get($table)) ? $routes->get($table)[$method] : $table;

        $id     = Id::create($tokens);
        $idPath = empty($id) ? '' : '/' . $id;

        return Assertions::isUrl($route) ? $route . $idPath : $apiUrl . '/' . $route . $idPath;
    }
}