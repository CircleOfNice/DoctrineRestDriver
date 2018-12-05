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
 * UpdateChangeSet type
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 */
class UpdateChangeSet {

    /**
     * Converts the string with format key="value",[key2="value2",]*
     * into json
     *
     * @param  array $tokens
     * @return string
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public static function create(array $tokens) {
        HashMap::assert($tokens, 'tokens');

        $columns = array_map(function($token) {
            $segments = explode('=', $token['base_expr'], 2);
            return trim($segments[0]);
        }, $tokens['SET']);

        $values = array_map(function($token) {
            $segments = explode('=', $token['base_expr'], 2);
            return Value::create(trim($segments[1]));
        }, $tokens['SET']);

        return array_combine($columns, $values);
    }
}
