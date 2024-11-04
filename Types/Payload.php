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
use Doctrine\Common\Collections\ArrayCollection;

/**
 * Payload type: Union type for InsertChangeSet and InsertChangeSet
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 */
class Payload {

    /**
     * Returns an InsertChangeSet::create or InsertChangeSet::create
     * result or null depending on the given tokens array
     *
     * @param  array       $tokens
     * @param  array       $options
     * @return null|string
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public static function create(array $tokens, array $options,$annotation = null) {
        HashMap::assert($tokens, 'tokens');

        $format    = Format::create($options);
        $operation = SqlOperation::create($tokens);

        $ret = null ;

        if ($operation === SqlOperations::INSERT)
            $input = InsertChangeSet::create($tokens) ;

        if ($operation === SqlOperations::UPDATE)
            $input = UpdateChangeSet::create($tokens) ;

        if ($operation === SqlOperations::INSERT || $operation === SqlOperations::UPDATE) {
            $transformer = Transform::create($options);

            $method = "post" ;

            if ($transformer && $input)
                $input = $transformer->transform($input,
                    new Request([
                        'method'              => HttpMethod::create($method, $annotation),
                        'url'                 => Url::createFromTokens($tokens, $options['host'], $annotation),
                        'curlOptions'         => CurlOptions::create(array_merge($options['driverOptions'], HttpHeader::create($options['driverOptions'], $tokens))),
                        'query'               => HttpQuery::create($tokens, $options['driverOptions']),
                        'payload'             => [ 'operation'=> $operation , 'token' =>  $tokens ] ,
                        'expectedStatusCodes' => StatusCode::create($method, $annotation)
                    ])) ;

            $ret = $format->encode($input);
        }


        return $ret ;

    }
}
