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

use Doctrine\Common\Persistence\ObjectManager;

/**
 * Provider for doctrine meta data
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 */
class MetaData {

    /**
     * @var ObjectManager
     */
    protected $em;

    /**
     * MetaData constructor
     */
    public function __construct() {
        $this->em = array_filter(debug_backtrace(), function($trace) {
            return isset($trace['object']) && $trace['object'] instanceof ObjectManager;
        });
    }

    /**
     * returns all namespaces of managed entities
     *
     * @return array
     */
    public function getEntityNamespaces() {
        return array_reduce($this->get(), function($carry, $item) {
            $carry[$item->table['name']] = $item->getName();
            return $carry;
        }, []);
    }

    /**
     * returns all entity meta data if existing
     *
     * @return array
     */
    public function get() {
        return empty($this->em) ? [] : array_pop($this->em)['object']->getMetaDataFactory()->getAllMetaData();
    }
}