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

use Doctrine\DBAL\Exception;
use Doctrine\DBAL\Query;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Component\HttpFoundation\Response;
use Doctrine\DBAL\Driver\DriverException as DriverExceptionInterface;
use Doctrine\DBAL\Exception as DBALException;

/**
 * Description of ResponseExceptionFactory
 *
 * @author Rob Treacy <robert.treacy@thesalegroup.co.uk>
 */
class ResponseExceptionFactory
{
    /**
     * Handle a failed response by creating a specific exception for the given
     * response.
     *
     * @param Response $response
     * @param DriverExceptionInterface $exception
     * @return DriverException
     */
    public function createDbalException(Response $response, $exception) {
        /** @var $exception Exception */

        switch ($response->getStatusCode()) {
            case Response::HTTP_BAD_REQUEST:
                return new DBALException\SyntaxErrorException($exception,null);

            case Response::HTTP_METHOD_NOT_ALLOWED:
            case Response::HTTP_NOT_ACCEPTABLE:
            case Response::HTTP_REQUEST_TIMEOUT:
            case Response::HTTP_LENGTH_REQUIRED:
            case Response::HTTP_INTERNAL_SERVER_ERROR:
                return new DBALException\ServerException($exception,null);

            case Response::HTTP_CONFLICT:
                return new DBALException\ConstraintViolationException($exception,null);

            case Response::HTTP_UNAUTHORIZED:
            case Response::HTTP_FORBIDDEN:
            case Response::HTTP_PROXY_AUTHENTICATION_REQUIRED:
            case Response::HTTP_BAD_GATEWAY:
            case Response::HTTP_SERVICE_UNAVAILABLE:
            case Response::HTTP_GATEWAY_TIMEOUT:
                return new DBALException\ConnectionException($exception,null);

            default:
                return new DBALException\DriverException( $exception,null);
        }
    }
}
