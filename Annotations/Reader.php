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

use Doctrine\Common\Annotations\AnnotationReader;
use Doctrine\ORM\Mapping\Driver\AttributeReader;
use Doctrine\ORM\Mapping\Driver\RepeatableAttributeCollection;
use Doctrine\ORM\Mapping\MappingAttribute;
use ReflectionAttribute;
use ReflectionClass;

/**
 * Reads annotations
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 */
class Reader {

    /**
     * @var AnnotationReader
     */
    private $annotationReader;
    private $attributeReader ;


    /**
     * Reader constructor.
     */
    public function __construct() {
//        $this->annotationReader = new AnnotationReader();
        $this->attributeReader = new AttributeReader() ;
    }

    /**
     * returns the route annotation value or null if no annotation exists
     *
     * @param  \ReflectionClass  $class
     * @param  string $namespace
     * @return null|string
     */
    public function read(\ReflectionClass $class, $namespace) {

        $attributes = $this->getClassAttributes($class);

        foreach ($attributes as $attribute)
        {
            if ($attribute instanceof $namespace)
                return $attribute ;
        }

        // get inherited annotations
        $parent = $class->getParentClass();
        if ($parent !== false) {
            return $this->read($parent, $namespace);
        }


        return null ; // @codeCoverageIgnore

//        $annotation = $this->annotationReader->getClassAnnotation($class, $namespace);
//        return $attributes instanceof $namespace ? $attributes : null;
//        return $annotation instanceof $namespace ? $annotation : null;
    }

    public function readAll(\ReflectionClass $class, $namespace) {

        $attributes = $this->getClassAttributes($class);

        $return = [] ;

        foreach ($attributes as $attribute)
        {
            if ($attribute instanceof $namespace) {
                if (!str_starts_with($attribute::class,__NAMESPACE__))
                    $return[$attribute::class] = $attribute;
            }
        }

        return $return ;

    }

    /**
     * @psalm-return class-string-map<T, T|RepeatableAttributeCollection<T>>
     *
     * @template T of MappingAttribute
     */
    public function getClassAttributes(ReflectionClass $class): array
    {
        return $this->convertToAttributeInstances($class->getAttributes());
    }

    /**
     * @param array<ReflectionAttribute> $attributes
     *
     * @return class-string-map<T, T|RepeatableAttributeCollection<T>>
     *
     * @template T of MappingAttribute
     */
    private function convertToAttributeInstances(array $attributes): array
    {
        $instances = [];

        foreach ($attributes as $attribute) {
            $attributeName = $attribute->getName();
            $instance = $attribute->newInstance();
            $instances[$attributeName] = $instance;
        }

        return $instances;
    }
}
