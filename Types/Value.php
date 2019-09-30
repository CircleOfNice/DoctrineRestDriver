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

use Circle\DoctrineRestDriver\Validation\Assertions;
use Circle\DoctrineRestDriver\Validation\Exceptions\InvalidTypeException;

/**
 * Value type
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 */
class Value {

    /**
     * Infers the type of a given string
     *
     * @param  string $value
     * @return string
     * @throws InvalidTypeException
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public static function create($value) {
        Str::assert($value, 'value');

        if($value === 'true')  return true;
        if($value === 'false') return false;
        if($value === 'null')  return null;

        $unquoted = preg_replace('/^(?|\"(.*)\"|\\\'(.*)\\\'|\`(.*)\`)$/sD', '$1', $value);
        if (!is_numeric($unquoted))                     return static::unquote($unquoted);
        if ((string) intval($unquoted) === $unquoted)   return intval($unquoted);
        if ((string) floatval($unquoted) === $unquoted) return floatval($unquoted);

        return $unquoted;
    }

    /**
     * undoes the quoting
     *
     * @param string $param
     *
     * @return string
     */
    public static function unquote($param) {
        return str_replace('\'\'', '\'', $param);
    }
}
