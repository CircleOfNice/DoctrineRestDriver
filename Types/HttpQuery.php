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

use Circle\DoctrineRestDriver\Enums\SqlOperations;
use Circle\DoctrineRestDriver\MetaData;
use Circle\DoctrineRestDriver\Validation\Assertions;

/**
 * HttpQuery type
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 */
class HttpQuery {

    /**
     * Creates a http query string by using the WHERE
     * clause of the parsed sql tokens
     *
     * @param  array $tokens
     * @return string|null
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public static function create(array $tokens) {
        HashMap::assert($tokens, 'tokens');

        $operation = SqlOperation::create($tokens);
        if ($operation !== SqlOperations::SELECT || empty($tokens['WHERE'])) return null;

        $tableAlias = Table::alias($tokens);
        $query      = array_reduce($tokens['WHERE'], function($query, $token) use ($tableAlias) {
            return $query . trim(str_replace('IN', '=', str_replace('"', '', str_replace('OR', '|', str_replace('AND', '&', str_replace($tableAlias . '.', '', $token['base_expr']))))), '()');
        });

        return preg_replace('/' . Identifier::column($tokens, new MetaData()) . '\=\d*&*/', '', $query);
    }
}