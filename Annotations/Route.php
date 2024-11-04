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

namespace Circle\DoctrineRestDriver\Annotations;

use Circle\DoctrineRestDriver\Types\MaybeList;
use Circle\DoctrineRestDriver\Types\MaybeString;
use Circle\DoctrineRestDriver\Types\Url;
use Doctrine\Common\Collections\ArrayCollection;

/**
 * Trait for all annotations regarding routes
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 * @Annotation
 */
trait Route {

    /**
     * @var string
     */
    private $route;

    /**
     * @var string
     */
    private $method;

    /**
     * @var int[]
     */
    private $statusCodes;

    /**
     * @var array
     */
    private $options = [];

    /**
     * Constructor
     *
     * @param array $values
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public function __construct($arrayOrUri,$statusCodes = null,$method = null,$options = [] ) {
        $values = $arrayOrUri;

        if (is_array($values)) {
            $settings = new ArrayCollection($values);
//            $this->route = Url::assert($settings->get('value'), 'value');
            if (substr($values,0,1) === "/")
                $this->route = substr($settings->get('value'),1);
            else
                $this->route = Url::assert($settings->get('value'), 'value');
            // permet absolute "/"
            $this->statusCodes = MaybeList::assert($settings->get('statusCodes'), 'statusCodes');
            $this->method = MaybeString::assert($settings->get('method'), 'method');
            $this->options = MaybeList::assert($settings->get('options'), 'options');
            if ($this->options === null)
                $this->options = [] ;

        }
        elseif (is_string($values)) {  // @codeCoverageIgnoreStart
            if (substr($values,0,1) === "/")
                $this->route = substr($values,1);
            else
                $this->route = Url::assert($values, 'value');
            // permet absolute "/"
            $this->statusCodes = $statusCodes;
            $this->method = $method;
            $this->options = $options;
            // @codeCoverageIgnoreEnd
        }
    }

    /**
     * returns the route
     *
     * @return string
     */
    public function getRoute() {
        return $this->route;
    }

    /**
     * returns the status code
     *
     * @return int[]|null
     */
    public function getStatusCodes() {
        return $this->statusCodes;
    }

    /**
     * returns the method
     *
     * @return string|null
     */
    public function getMethod() {
        return $this->method;
    }

    /**
     * returns the options
     *
     * @return array|null
     */
    public function getOptions() {
        return $this->options;
    }
}
