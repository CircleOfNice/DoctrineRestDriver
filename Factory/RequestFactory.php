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

namespace Circle\DoctrineRestDriver\Factory;

use Circle\DoctrineRestDriver\Enums\HttpMethods;
use Circle\DoctrineRestDriver\Types\HttpHeader;
use Circle\DoctrineRestDriver\Types\CurlOptions;
use Circle\DoctrineRestDriver\Types\Payload;
use Circle\DoctrineRestDriver\Types\HttpQuery;
use Circle\DoctrineRestDriver\Types\LimitHttpHeader;
use Circle\DoctrineRestDriver\Types\OrderHttpHeader;
use Circle\DoctrineRestDriver\Types\Request;
use Circle\DoctrineRestDriver\Types\SqlOperation;
use Circle\DoctrineRestDriver\Types\Url;

/**
 * Factory for requests
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 * @SuppressWarnings("PHPMD.StaticAccess")
 */
class RequestFactory {

    /**
     * Creates a new Request with the given options
     *
     * @param  array   $tokens
     * @param  string  $apiUrl
     * @param  array   $options
     * @return Request
     */
    public function createOne(array $tokens, $apiUrl, array $options) {
        $method  = HttpMethods::ofSqlOperation(SqlOperation::create($tokens));
        $url     = Url::create($tokens, $apiUrl, $options);
        $query   = HttpQuery::create($tokens);
        $payload = $method === HttpMethods::GET || $method === HttpMethods::DELETE ? null : Payload::create($tokens);

        $options = array_merge($options, HttpHeader::create($options, $tokens));

        return new Request($method, $url, CurlOptions::create($options), $query, $payload);
    }
}
