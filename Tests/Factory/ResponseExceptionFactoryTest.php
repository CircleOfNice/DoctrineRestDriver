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

namespace Circle\DoctrineRestDriver\Tests\Factory;

use Circle\DoctrineRestDriver\Factory\ResponseExceptionFactory;
use Doctrine\DBAL\Exception;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;
use Doctrine\DBAL\Driver\Exception as DriverExceptionInterface;
use Doctrine\DBAL\Exception as DBALException;
/**
 *
 * @author Rob Treacy <robert.treacy@thesalegroup.co.uk>
 */
#[\PHPUnit\Framework\Attributes\CoversClass(ResponseExceptionFactory::class)]
class ResponseExceptionFactoryTest extends \PHPUnit\Framework\TestCase {
    private $responseExceptionFactory;

    public function setUp(): void
    {
        $this->responseExceptionFactory = new ResponseExceptionFactory;
    }

    /**
     * @test
     * @group  unit
     * @covers ::createDbalException
     */
    #[DataProvider('createDbalExceptionProvider')]
    #[Test]
    #[Group('unit')]
    public static function createDbalException(Response $response, $expectedExceptionClass) {
        $instanceMe = new self(self::class) ;
        $instanceMe->responseExceptionFactory = new ResponseExceptionFactory;
        $exception = $instanceMe->createMock($expectedExceptionClass) ;
        $return = $instanceMe->responseExceptionFactory->createDbalException($response, $exception);
        $instanceMe->assertInstanceOf(DriverExceptionInterface::class, $return);
    }

    /**
     * Data provider for createDbalException test
     */
    public static function createDbalExceptionProvider() {
        $instanceMe = new self(self::class) ;

        return array(
            [$instanceMe->createResponseFromCode(Response::HTTP_BAD_REQUEST), DBALException\SyntaxErrorException::class],
            [$instanceMe->createResponseFromCode(Response::HTTP_METHOD_NOT_ALLOWED), DBALException\ServerException::class],
            [$instanceMe->createResponseFromCode(Response::HTTP_NOT_ACCEPTABLE), DBALException\ServerException::class],
            [$instanceMe->createResponseFromCode(Response::HTTP_REQUEST_TIMEOUT), DBALException\ServerException::class],
            [$instanceMe->createResponseFromCode(Response::HTTP_LENGTH_REQUIRED), DBALException\ServerException::class],
            [$instanceMe->createResponseFromCode(Response::HTTP_INTERNAL_SERVER_ERROR), DBALException\ServerException::class],
            [$instanceMe->createResponseFromCode(Response::HTTP_CONFLICT), DBALException\ConstraintViolationException::class],
            [$instanceMe->createResponseFromCode(Response::HTTP_UNAUTHORIZED), DBALException\ConnectionException::class],
            [$instanceMe->createResponseFromCode(Response::HTTP_FORBIDDEN), DBALException\ConnectionException::class],
            [$instanceMe->createResponseFromCode(Response::HTTP_PROXY_AUTHENTICATION_REQUIRED), DBALException\ConnectionException::class],
            [$instanceMe->createResponseFromCode(Response::HTTP_BAD_GATEWAY), DBALException\ConnectionException::class],
            [$instanceMe->createResponseFromCode(Response::HTTP_SERVICE_UNAVAILABLE), DBALException\ConnectionException::class],
            [$instanceMe->createResponseFromCode(Response::HTTP_GATEWAY_TIMEOUT), DBALException\ConnectionException::class],
            [$instanceMe->createResponseFromCode(Response::HTTP_OK), DBALException\DriverException::class],
        );
    }

    private function createResponseFromCode($responseCode) {
        return new Response('Return with ' . $responseCode, $responseCode);
    }
}
