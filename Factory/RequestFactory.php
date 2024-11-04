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

use Circle\DoctrineRestDriver\Annotations\DataSource;
use Circle\DoctrineRestDriver\Types\HttpHeader;
use Circle\DoctrineRestDriver\Types\CurlOptions;
use Circle\DoctrineRestDriver\Types\HttpMethod;
use Circle\DoctrineRestDriver\Types\Payload;
use Circle\DoctrineRestDriver\Types\HttpQuery;
use Circle\DoctrineRestDriver\Types\Request;
use Circle\DoctrineRestDriver\Types\StatusCode;
use Circle\DoctrineRestDriver\Types\Url;

/**
 * Factory for requests
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 */
class RequestFactory {

    /**
     * Creates a new Request with the given options
     *
     * @param  string     $method
     * @param  array      $tokens
     * @param  array      $options
     * @param  DataSource $annotation
     * @return Request
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function createOne($method, array $tokens, array $options, DataSource $annotation = null) {
        return new Request([
            'method'              => HttpMethod::create($method, $annotation),
            'url'                 => Url::createFromTokens($tokens, $options['host'], $annotation),
            'curlOptions'         => CurlOptions::create(array_merge($options['driverOptions'], HttpHeader::create($options['driverOptions'], $tokens))),
            'query'               => HttpQuery::create($tokens, $options['driverOptions']),
            'payload'             => Payload::create($tokens, $options,$annotation),
            'expectedStatusCodes' => StatusCode::create($method, $annotation)
        ]);
    }
}
