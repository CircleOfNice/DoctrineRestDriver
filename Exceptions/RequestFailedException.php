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

namespace Circle\DoctrineRestDriver\Exceptions;

use Doctrine\DBAL\Driver\Exception as DriverException;
use Circle\DoctrineRestDriver\Types\Request;

/**
 * Exception class for failed requests
 * Thrown if a request's response does not return http status 200
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 * @SuppressWarnings("PHPMD.StaticAccess")
 */
class RequestFailedException extends DoctrineRestDriverException implements DriverException {

    /**
     *
     * @var int
     */
    private $errorCode;

    /**
     * RequestFailedException constructor
     *
     * @param Request $request
     * @param int     $errorCode
     * @param string  $errorMessage
     */
    public function __construct(Request $request, $errorCode, $errorMessage) {
        $this->errorCode = $errorCode;
        parent::__construct('Execution failed for request: ' . $request . ': HTTPCode ' . $errorCode . ', body ' . $errorMessage, $errorCode);
    }

    public function getErrorCode() {
        return $this->errorCode;
    }

    public function getSQLState() {
        return null;
    }

}
