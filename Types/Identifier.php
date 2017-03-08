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

use Circle\DoctrineRestDriver\MetaData;
use Circle\DoctrineRestDriver\Validation\Assertions;

/**
 * Extracts id information from a sql token array
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 */
class Identifier {

    /**
     * Returns the id in the WHERE clause if exists
     *
     * @param  array  $tokens
     * @return string
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public static function create(array $tokens) {
        HashMap::assert($tokens, 'tokens');

        if (empty($tokens['WHERE'])) return '';

        $idAlias = self::alias($tokens);

        return array_reduce($tokens['WHERE'], function($carry, $token) use ($tokens, $idAlias) {
            if (!is_int($carry)) return $carry;
            if ($token['expr_type'] === 'colref' && $token['base_expr'] === $idAlias && !in_array($tokens['WHERE'][$carry+2]['expr_type'], array('in-list'))) return $tokens['WHERE'][$carry+2]['base_expr'];
            if (!isset($tokens[$carry+1])) return '';
        }, 0);
    }

    /**
     * Returns the id alias
     *
     * @param  array $tokens
     * @return string
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public static function alias(array $tokens) {
        $column     = self::column($tokens, new MetaData());
        $tableAlias = Table::alias($tokens);

        return empty($tableAlias) ? $column : $tableAlias . '.' . $column;
    }

    /**
     * returns the column of the id
     *
     * @param  array    $tokens
     * @param  MetaData $metaData
     * @return string
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public static function column(array $tokens, MetaData $metaData) {
        $table = Table::create($tokens);
        $meta  = array_filter($metaData->get(), function($meta) use ($table) {
            return $meta->getTableName() === $table;
        });

        $idColumns  = !empty($meta) ? end($meta)->getIdentifierColumnNames() : [];

        if (empty($idColumns)) {
            foreach ($tokens['SELECT'] as $key => $token) {
                if ($token['expr_type'] == 'reserved') {
                    array_splice($tokens['SELECT'], $key, 1);
                }
            }
        }

        return !empty($idColumns) ? end($idColumns) : end($tokens['SELECT'][0]['no_quotes']['parts']);
    }
}