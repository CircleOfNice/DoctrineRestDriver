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

namespace Circle\DoctrineRestDriver\Tests\Security;

use Circle\DoctrineRestDriver\Enums\HttpMethods;
use Circle\DoctrineRestDriver\Security\HttpAuthentication;
use Circle\DoctrineRestDriver\Types\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;

/**
 * Tests the result mapping
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 */
#[CoversClass(HttpAuthentication::class)]
#[CoversMethod(HttpAuthentication::class,'__construct')]
#[CoversMethod(HttpAuthentication::class,'transformRequest')]
class HttpAuthenticationTest extends \PHPUnit\Framework\TestCase {

    /**
     * @var HttpAuthentication
     */
    private $authentication;

    /**
     * {@inheritdoc}
     */
    public function setUp() : void {
        $this->authentication = new HttpAuthentication([
            'host'          => 'http://circle.ai',
            'user'          => 'Aladdin',
            'password'      => 'OpenSesame',
            'driverOptions' => []
        ]);
    }

    #[Test]
    #[Group('unit')]
    public function transformRequest() {
        $expectedOptions = [
            CURLOPT_HTTPHEADER => [
                'Authorization: Basic QWxhZGRpbjpPcGVuU2VzYW1l'
            ]
        ];

        $request  = new Request([
            'method' => HttpMethods::GET,
            'url'    => 'http://circle.ai'
        ]);

        $expected = new Request([
            'method'      => HttpMethods::GET,
            'url'         => 'http://circle.ai',
            'curlOptions' => $expectedOptions
        ]);

        $this->assertEquals($expected, $this->authentication->transformRequest($request));
    }
}
