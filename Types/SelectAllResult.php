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
 * Doctrine result for SELECT ... without WHERE id = <id>
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 */
class SelectAllResult {

    /**
     * Returns a valid Doctrine result for SELECT ... without WHERE id = <id>
     *
     * @param  array  $tokens
     * @param  array  $content
     * @return string
     *
     * @SuppressWarnings("PHPMD.StaticAccess")
     */
    public static function create(array $tokens, array $content) {
        $content = self::orderBy($tokens, $content);
        $content = array_map(function($entry) use ($tokens) {
            $row = SelectSingleResult::create($tokens, $entry);
            return array_pop($row);
        }, $content);

        return $content ;
    }

    /**
     * Orders the content with the given order by criteria
     *
     * @param  array $tokens
     * @param  array $content
     * @return array
     */
    public static function orderBy(array $tokens, array $content) {
        if (empty($tokens['ORDER'])) return $content;

        $sortingRules = array_map(function($token) use ($content) {
            return [
                end($token['no_quotes']['parts']),
                $token['direction']
            ];
        }, $tokens['ORDER']);

        $reducedSortingRules = array_reduce($sortingRules, 'array_merge', []);
        $sortArgs            = array_map(function($value) use ($content) {
            if ($value === 'ASC')  return SORT_ASC;
            if ($value === 'DESC') return SORT_DESC;

            $contents = [];
            foreach ($content as $c) array_push($contents, $c[$value]);
            return $contents;
        }, $reducedSortingRules);

        $sortArgs[] = &$content;
        call_user_func_array('array_multisort', $sortArgs);

        return end($sortArgs);
    }
}
