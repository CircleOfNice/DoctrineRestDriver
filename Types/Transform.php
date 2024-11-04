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

use Circle\DoctrineRestDriver\Exceptions\Exceptions;
use Circle\DoctrineRestDriver\Exceptions\InvalidAuthStrategyException;
use Circle\DoctrineRestDriver\Transformers\Transformer;
use Circle\DoctrineRestDriver\Validation\Assertions;

/**
 * Type for Transform
 *
 * @author    David nurdin <david.nurdin@respawnsive.com>
 */
class Transform {

    /**
     * Returns the right format
     *
     * @param  array  $options
     * @return Transformer
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public static function create(array $options) {
        $transformerClass = ucfirst(!empty($options['driverOptions']['transformer']) ? $options['driverOptions']['transformer'] : 'dummy');
        if (!empty($transformerClass)) {
            $className = preg_match('/\\\\/', $transformerClass) ? $transformerClass : 'Circle\DoctrineRestDriver\Transformers\\' . $transformerClass;
            Assertions::assertClassExists($className);
            return self::assert(new $className($options));
        }

    }

    /**
     * Checks if the given instance is instanceof Formatter
     *
     * @param  object $instance
     * @return null
     * @throws InvalidAuthStrategyException
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public static function assert($instance) {
        return !$instance instanceof Transformer ? Exceptions::invalidFormatException(get_class($instance)) : $instance;
    }
}
