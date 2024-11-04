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

namespace Circle\DoctrineRestDriver\Tests;

use Circle\DoctrineRestDriver\Enums\HttpMethods;
use Circle\DoctrineRestDriver\RestClient;
use Circle\DoctrineRestDriver\Types\Request;
use Doctrine\DBAL\Exception\DriverException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * Tests the rest client
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 */
#[CoversClass(RestClient::class)]
#[CoversMethod(RestClient::class, 'send')]
#[CoversMethod(RestClient::class, '__construct')]
class RestClientTest extends \PHPUnit\Framework\TestCase {

    /**
     * @var RestClient
     */
    private $restClient;

    /**
     * {@inheritdoc}
     */
    public function setUp(): void
    {
        $this->restClient = new RestClient();
    }

    #[Test]
    #[Group('unit')]
    public function send() {
        $request = new Request([
            'method' => HttpMethods::GET,
            'url'    => 'http://127.0.0.1:3000/app_dev.php/mockapi/products/1'
        ]);

        $response = new Response(json_encode([
            'id'                          => 1,
            'extremelyStrange_identifier' => 1,
            'name'                        => 'MyName',
            'value'                       => 'MyValue'
        ]));

        $this->assertEquals($response->getContent(), $this->restClient->send($request)->getContent());
    }

    #[Test]
    #[Group('unit')]
    public function sendFail() {
        $request = new Request([
            'method' => HttpMethods::GET,
            'url'    => 'http://127.0.0.1:3000/app_dev.php/mockapi/products/NOT_EXIST'
        ]);


        $this->expectException(\Circle\DoctrineRestDriver\Exceptions\RequestFailedException::class);
        $this->expectException(DriverException::class);
        $this->assertEquals('', $this->restClient->send($request)->getContent());
    }
}
