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
use Circle\DoctrineRestDriver\Exceptions\Exceptions;
use Circle\DoctrineRestDriver\Validation\Assertions;
use Circle\DoctrineRestDriver\Validation\Exceptions\InvalidTypeException;

/**
 * Url type
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 */
class Url {

    /**
     * returns an url depending on the given route, apiUrl
     * and id
     *
     * @param  string      $route
     * @param  string      $apiUrl
     * @param  string|null $id
     * @return string
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public static function create($route, $apiUrl, $id = null) {
        Str::assert($route, 'route');
        Str::assert($apiUrl, 'apiUrl');
        MaybeString::assert($id, 'id');

        $idPath = empty($id) ? '' : '/' . rawurlencode($id);

        if (!self::is($route))               return $apiUrl . '/' . $route . $idPath;
        if (!preg_match('/\{id\}/', $route)) return $route . $idPath;
        if (!empty($id))                     return str_replace('{id}', rawurlencode($id), $route);

        return str_replace('/{id}', '', $route);
    }

    /**
     * returns an url depending on the given tokens
     *
     * @param  array      $tokens
     * @param  string     $apiUrl
     * @param  DataSource $annotation
     * @return string
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public static function createFromTokens(array $tokens, $apiUrl, DataSource $annotation = null) {
        $id    = Identifier::create($tokens);
        $route = empty($annotation) || $annotation->getRoute() === null ? Table::create($tokens) : $annotation->getRoute();

        return self::create($route, $apiUrl, $id);
    }

    /**
     * Checks if the given value is an url
     *
     * @param  $value
     * @return bool
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public static function is($value) {
        return (bool) (preg_match('/^(http|ftp|https):\/\/([0-9a-zA-Z_-]+(\.[0-9a-zA-Z_-]+)+|localhost)([0-9a-zA-Z_\-.,@?^=%&amp;:\/~+#-]*[0-9a-zA-Z_\-@?^=%&amp;\/~+#-])?/', $value));
    }

    /**
     * Asserts if the given value is an url
     *
     * @param  mixed  $value
     * @param  string $varName
     * @return string
     * @throws InvalidTypeException
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public static function assert($value, $varName) {
        return !self::is($value) ? Exceptions::InvalidTypeException('Url', $varName, $value) : $value;
    }
}
