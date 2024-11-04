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

namespace Circle\DoctrineRestDriver\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Mock controller for functional testing
 *
 * @author    Tobias Hauck <tobias@circle.ai>
 * @copyright 2015 TeeAge-Beatz UG
 */
class MockController extends AbstractController {

    /**
     * Mock action for testing get
     *
     * @param  string   $id
     * @return Response
     */
    public function getAction($id) {
        if ($id == 500) return new Response('', 500);
        if ($id != 1) return new Response('', 404);


        return new Response(json_encode([
            'id'                          => 1,
            'extremelyStrange_identifier' => 1,
            'name'                        => 'MyName',
            'value'                       => 'MyValue',
        ]));
    }

    /**
     * Mock action for testing getAll
     *
     * @return Response
     */
    public function getAllAction() {
        return new Response(json_encode([
            [
                'id'    => 1,
                'name'  => 'MyName',
                'value' => 'MyValue',
            ],
            [
                'id'    => 2,
                'name'  => 'NextName',
                'value' => 'NextValue',
            ]
        ]));
    }

    /**
     * Mock action for testing post
     *
     * @param  Request  $request
     * @return Response
     */
    public function postAction(Request $request) {
        $payload = json_decode($request->getContent());

        return new Response(json_encode([
            'id'    => 1,
            'name'  => $payload->name,
            'value' => $payload->value,
        ]), 201);
    }

    /**
     * Mock action for testing put
     *
     * @param  string   $id
     * @return Response
     */
    public function putAction($id) {
        if ($id != 1) return new Response('', 404);

        return new Response(json_encode([
            'id'    => 1,
            'name'  => 'MyName',
            'value' => 'MyValue',
        ]));
    }

    /**
     * Mock action for testing delete
     *
     * @param  string   $id
     * @return Response
     */
    public function deleteAction($id) {
        if ($id != 1) return new Response('', 404);

        return new Response('', 204);
    }

    public function getAllCategoriesAction(Request $request) {

        $result = [
            [
                'id'         => 1,
                'name'       => 'CategMyName',
                'product_id' => 1,
            ],
            [
                'id'         => 2,
                'name'       => 'CategNextName',
                'product_id' => 1,
            ],
            [
                'id'         => 3,
                'name'       => 'OtherCategMyName',
                'product_id' => 2,
            ]
        ] ;

        $product_id = $request->get('product_id',null);


        if ($product_id)
        {
            $results = [] ;

            foreach ($result as $r)
            {
                if ($r['product_id'] != $product_id)
                {
                    $results[] = $r ;
                }

            }

            $result = $results ;

        }
        return new Response(json_encode($result),200);
    }

    /**
     * Mock action for testing associated entities
     *
     * @param  Request  $request
     * @return Response
     */
    public function postCategoriesAction(Request $request) {
        $payload = json_decode($request->getContent());

        return new Response(json_encode([
            'id'         => 1,
            'name'       => $payload->name,
            'product_id' => $payload->product_id,
        ]), 201);
    }
}
