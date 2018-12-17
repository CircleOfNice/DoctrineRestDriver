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

/**
 * Maps the response content of a GET query to a valid
 * Doctrine result for SELECT ... WHERE id = <id>
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 */
class SelectSingleResult {

    /**
     * Returns a valid Doctrine result for SELECT ... WHERE id = <id>
     *
     * @param  array  $tokens
     * @param  array  $content
     * @return string
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public static function create(array $tokens, $content) {
        HashMap::assert($tokens, 'tokens');
        $tableAlias = Table::alias($tokens);

        $attributeValueMap = array_map(function($token) use ($content, $tableAlias) {
            $key   = str_replace('`', '', empty($token['alias']['name']) ? $token['base_expr'] : $token['alias']['name']);
            $value = $content[str_replace([$tableAlias . '.', '`'], '', $token['base_expr'])];
            return [$key => $value];
        }, $tokens['SELECT']);

        return [ array_reduce($attributeValueMap, 'array_merge', []) ];
    }
}
