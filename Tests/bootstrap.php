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

/**
 * This file provides the bootstrapping for testing
 *
 * @author    tobias.hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 */

// exec('composer dumpautoload');
$file = __DIR__.'/../vendor/autoload.php';
if (!file_exists($file)) {
    echo "\n\e[1;31m"  . 'Install dependencies to run test suite. Run "composer install".' . "\e[0m\n\n";
    exit();
}

$autoload = require_once $file;

return $autoload;
