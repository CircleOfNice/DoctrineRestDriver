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
use Circle\DoctrineRestDriver\Validation\Assertions;
use PHPSQLParser\PHPSQLParser;

/**
 * Maps the response content of any query to a valid
 * Doctrine result
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 */
class Result {

    /**
     * Returns a valid Doctrine result
     *
     * @param  string $query
     * @param  array  $content
     * @return string
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public static function create($query, $content) {
        $queryParts = explode(' ', $query);
        $transformedQuery = array_reduce($queryParts, function($carry, $part) {
            return $carry . (Assertions::isUrl($part) ? (' "' . $part . '" ') : ($part . ' '));
        });
        $parser   = new PHPSQLParser();
        $tokens   = $parser->parse($transformedQuery);
        $operator = strtolower(array_keys($tokens)[0]);

        if ($operator === SqlOperations::DELETE) return [];
        return $operator === SqlOperations::SELECT ? SelectResult::create($tokens, $content) : $content;
    }
}
