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

namespace Circle\DoctrineRestDriver;

use Circle\DoctrineRestDriver\Enums\HttpMethods;
use Circle\DoctrineRestDriver\Exceptions\Exceptions;
use Circle\DoctrineRestDriver\Factory\RestClientFactory;
use Circle\DoctrineRestDriver\Types\Request;
use Symfony\Component\HttpFoundation\Response;
use Circle\RestClientBundle\Services\RestClient as CiRestClient;
use Circle\DoctrineRestDriver\Exceptions\RequestFailedException;

/**
 * Rest client to send requests and map responses
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 */
class RestClient {

    /**
     * @var CiRestClient
     */
    protected $restClient;

    /**
     * RestClient constructor
     */
    public function __construct() {
        $this->restClient = (new RestClientFactory())->createOne([]);
    }

    /**
     * sends the request
     *
     * @param  Request $request
     * @return Response
     * @throws RequestFailedException
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function send(Request $request) {
        $method     = strtolower($request->getMethod());
        $response   = $method === HttpMethods::GET || $method === HttpMethods::DELETE ? $this->restClient->$method($request->getUrlAndQuery(), $request->getCurlOptions()) : $this->restClient->$method($request->getUrlAndQuery(), $request->getPayload(), $request->getCurlOptions());

        return $response->getStatusCode() === $request->getExpectedStatusCode() ? $response : Exceptions::RequestFailedException($request, $response->getStatusCode(), $response->getContent());
    }
}