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

use Circle\DoctrineRestDriver\Enums\SqlOperations;
use Circle\DoctrineRestDriver\Validation\Assertions;
use Doctrine\Common\Collections\ArrayCollection;
use Symfony\Component\Yaml\Yaml;

/**
 * Type to create an ArrayCollection containing all routes
 * from the configuration file
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 */
class Routes {

    /**
     * Returns an ArrayCollection of all routes configurated
     * in the rest_driver_config.yml file
     *
     * @param  array           $options
     * @return ArrayCollection
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public static function create(array $options) {
        Assertions::assertHashMap('options', $options);

        return !empty($options['routes']) ? new ArrayCollection(Yaml::parse(file_get_contents($options['routes']))['routes']) : new ArrayCollection();
    }
}