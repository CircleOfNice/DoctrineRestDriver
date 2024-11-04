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
 * Request type
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 */
class Request {

    /**
     * @var string
     */
    private $method;

    /**
     * @var string
     */
    private $url;

    /**
     * @var string
     */
    private $payload;

    /**
     * @var array
     */
    private $curlOptions = [];

    /**
     * @var string
     */
    private $query;

    /**
     * @var int
     */
    private $expectedStatusCodes = [200];

    /**
     * Request constructor
     *
     * @param array $options
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function __construct(array $options) {
        HashMap::assert($options, 'options');
        HashMapEntry::assertExists($options, 'method', 'options.method');
        HashMapEntry::assertExists($options, 'url', 'options.url');

        foreach($options as $key => $value) $this->$key = $value;
    }

    public function setQuery($query)
    {
        $this->query = $query ;
    }

    /**
     * sets the curl options
     *
     * @param  array $options
     * @return Request
     */
    public function setCurlOptions(array $options) {
        return new Request([
            'method'              => $this->method,
            'url'                 => $this->url,
            'curlOptions'         => $options,
            'query'               => $this->query,
            'payload'             => $this->payload,
            'expectedStatusCodes' => $this->expectedStatusCodes
        ]);
    }

    /**
     * Returns the method
     *
     * @return string
     */
    public function getMethod() {
        return $this->method;
    }

    /**
     * Returns the url
     *
     * @return string
     */
    public function getUrl() {
        return $this->url;
    }

    /**
     * returns the payload
     *
     * @return string
     */
    public function getPayload() {
        return $this->payload;
    }

    /**
     * Returns all curl options
     *
     * @return array
     */
    public function getCurlOptions() {
        return $this->curlOptions;
    }

    /**
     * Returns the query
     *
     * @return string
     */
    public function getQuery() {
        return $this->query;
    }

    /**
     * Returns the url with query
     *
     * @return string
     */
    public function getUrlAndQuery() {
        return $this->url . '?' . $this->query;
    }

    /**
     * returns whether the given status code is expected
     *
     * @return bool
     */
    public function isExpectedStatusCode($statusCode) {
        return in_array($statusCode, $this->expectedStatusCodes);
    }

    /**
     * {@inheritdoc}
     */
    public function __toString() {
        return strtoupper($this->method) . ' ' . $this->getUrlAndQuery() . ' HTTP/1.1' . (!empty($this->payload) ? ' ' . $this->payload : '');
    }
}
