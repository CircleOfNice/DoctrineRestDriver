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

/**
 * InsertChangeSet type
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 */
class InsertChangeSet {

    /**
     * Converts the string with format (key) VALUES (value)
     * into json
     *
     * @param  array $tokens
     * @return string
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public static function create(array $tokens) {
        HashMap::assert($tokens, 'tokens');

        return array_combine(self::columns($tokens), self::values($tokens));
    }

    /**
     * returns the columns as list
     *
     * @param  array $tokens
     * @return array
     */
    public static function columns(array $tokens) {
        $columns = array_filter($tokens['INSERT'], function($token) {
            return $token['expr_type'] === 'column-list';
        });

        return array_map(function($column) {
            return end($column['no_quotes']['parts']);
        }, end($columns)['sub_tree']);
    }

    /**
     * returns the values as list
     *
     * @param  array $tokens
     * @return array
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public static function values(array $tokens) {
        $values = [] ;

        foreach (end($tokens['VALUES'])['data'] as $value) {
            $values[] = $value['base_expr'];
        }

        return array_map(function($value) {
            return Value::create($value);
        }, $values);
    }

    /**
     * removes spaces between commas
     *
     * @param  string $string
     * @return string
     */
    private static function removeSpacesBetweenComma($string) {
        return str_replace(', ', ',', $string);
    }

    /**
     * removes beginning and ending brackets
     *
     * @param  string $string
     * @return string
     */
    private static function removeBrackets($string) {
        return preg_replace('/\)$/', '', preg_replace('/^\(/', '', $string));
    }
}
