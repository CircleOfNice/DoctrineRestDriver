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
     *
     * @return array|bool
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     * @throws \Circle\DoctrineRestDriver\Validation\Exceptions\InvalidTypeException
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
        $values = self::removeBrackets(end($tokens['VALUES'])['base_expr']);

        return array_map(function($value) {
            return Value::create($value);
        }, static::parseValueStringToArray($values));
    }

    /**
     * parses the values string into a an array that has the correct amount of values, compared with the column array.
     *
     * @see isCharStringDelimiter for a list of valid string starting characters.
     * @see SqlQuery::quote() for the place where the automatic escape happens
     *
     * @param string $values
     *
     * @return array
     */
    private static function parseValueStringToArray($values) {
        $valueArray        = [''];
        $currentValue      = 0;
        $stringOffset      = 0;
        $isString          = false;
        $stringStartedWith = null;

        while (($char = substr($values, $stringOffset++, 1)) !== false)
        {
            // Handle the beginning, ending and escaping of characters
            if (static::isCharStringDelimiter($char, $stringStartedWith)) {
                $stringStartedWith = null;

                // Set the string that started this string sequence and also define it as the current escape character
                if ($isString === false) {
                    $stringStartedWith = $char;
                }

                // toggle string mode
                $isString = !$isString;
            }

            // move the current value pointer to the next array key and create an empty string in it.
            if (!$isString && $char === ',') {
                $valueArray[++$currentValue] = '';
                continue;
            }

            // skip whitespace characters when the current value is not flagged as a string
            if (!$isString && preg_match('/\s/', $char)) {
                continue;
            }

            // simply append the current character at the current array position
            $valueArray[$currentValue] .= $char;
        }

        return $valueArray;
    }

    /**
     * Checks if the character is on the list of starting characters
     *
     * @param string $char
     *
     * @return bool
     */
    private static function isStringStartingCharacter($char) {
        return $char === '\'' || $char === '"' || $char === '`';
    }

    /**
     * Checks if the character is on the list of starting characters and if it's identical to the starting character of
     * the current string.
     *
     * @param string      $char
     * @param string|null $startingChar
     *
     * @return bool
     */
    private static function isCharStringDelimiter($char, $startingChar) {
        return static::isStringStartingCharacter($char)
               && ($char === $startingChar || $startingChar === null);
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
