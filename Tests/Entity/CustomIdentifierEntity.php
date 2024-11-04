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

namespace Circle\DoctrineRestDriver\Tests\Entity;

use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Collections\Collection;
use Doctrine\ORM\Mapping as ORM;
use Circle\DoctrineRestDriver\Annotations as DataSource;

/**
 * This is a test entity with a strange named identifier
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 *
 * @SuppressWarnings("PHPMD")
 */
#[ORM\Entity]
#[ORM\Table(name: "other_products")]
class CustomIdentifierEntity {
    /**
     * @var int
     */
    #[ORM\Column(type: "integer")]
    #[ORM\Id]
    #[ORM\GeneratedValue(strategy: "AUTO")]
    protected $extremelyStrange_identifier;

    /**
     * @return int
     */
    public function getId() {
        return $this->extremelyStrange_identifier;
    }

    /**
     * @param  int                    $id
     * @return CustomIdentifierEntity
     */
    public function setId($id) {
        $this->extremelyStrange_identifier = $id;
        return $this;
    }
}
