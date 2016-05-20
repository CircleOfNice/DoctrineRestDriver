# Motivation
What does a black sheep and a white sheep have in common? They produce wool.<br />
What does a big bus and a small bus have in common? They drive people around.<br />
And what does a SQL database and a REST API have in common? They store data.<br />

As blatantly obvious as this sounds the consequences are tremendous: With REST APIs being nothing more than data storage backends, we are able to reuse object relational mapping tools to access them.

And because we have absolutely no idea how to write a programming language, we're tryin to do it like Rasmus and keep adding the next logical step on the way. So DoctrineRestDriver saw the light of day.

# Prerequisites

- You need composer to download the library
- Your REST API has to return JSON and to adhere to the following rules:
    - Use POST to create new data
        - Urls have the following format: ```http://www.host.de/path/to/api/entityName```
        - Use the request body to receive data
        - Respond with HTTP code 200 if successful
        - Fill the response body with the given payload plus an id
    - Use PUT to change data
        - Urls have the following format: ```http://www.host.de/path/to/api/entityName/<id>```
        - Use the request body to receive data
        - Respond with HTTP code 200 if successful
        - Fill the response body with the given payload
    - Use DELETE to remove data
        - Urls have the following format: ```http://www.host.de/path/to/api/entityName/<id>```
        - The request body must be empty
        - Respond with HTTP code 204 if successful
        - The response body must be empty
    - Use GET to receive data
        - Urls have the following format: ```http://www.host.de/path/to/api/entityName/<id>``` or ```http://www.host.de/path/to/api/entityName```
        - Use HTTP query strings as filters
        - Respond with HTTP code 200 if successful
        - Fill the response body with the read data

# Installation

Add the driver to your project using composer:

```php
composer require circle/doctrine-rest-driver
```

Change the following doctrine dbal configuration entries:

```yml
doctrine:
  dbal:
    driver_class: "Circle\\DoctrineRestDriver\\Driver"
    host:         "%default_api_url%"
    port:         "%default_api_port%"
    user:         "%default_api_username%"
    password:     "%default_api_password%"
    options:
      authentication_class:  "HttpAuthentication" | "YourOwnNamespaceName" | if not specified no authentication will be used
      routes:                "%kernel.root_dir%/config/rest_driver_routing.yml"
```

Additionally you can add CURL-specific options:

```yml
doctrine:
  dbal:
    driver_class: "Circle\\DoctrineRestDriver\\Driver"
    host:         "%default_api_url%"
    port:         "%default_api_port%"
    user:         "%default_api_username%"
    password:     "%default_api_password%"
    options:
      authentication_class:           "HttpAuthentication"
      routes:                         "%kernel.root_dir%/config/rest_driver_routing.yml"
      CURLOPT_CURLOPT_FOLLOWLOCATION: true
      CURLOPT_HEADER:                 true
```

A full list of all possible options can be found here: http://php.net/manual/en/function.curl-setopt.php

# Usage

The following code samples show how to use the driver in a Symfony environment. This configuration will be used:

```yml
doctrine:
  dbal:
    driver_class: "Circle\\DoctrineRestDriver\\Driver"
    host:         "http://www.your-url.com/api"
    port:         80
    user:         "Circle"
    password:     "CantRemember"
```

First of all create your entities:

```php
namespace CircleBundle\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * This annotation marks the class as managed entity:
 *
 * @ORM\Entity
 *
 * You can either only use a resource name or the whole url of
 * the resource to define your target. In the first case the target 
 * url will consist of the host, configured in your options and the 
 * given name. In the second one your argument is used as it is.
 * Important: The resource name must begin with its protocol.
 *
 * @ORM\Table("products|http://www.yourSite.com/api/products")
 */
class Product {

    /**
     * @ORM\Column(type="integer")
     * @ORM\Id
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    private $id;
    
    /**
     * @ORM\Column(type="string", length=100)
     */
    private $name;
    
    public function getId() {
        return $this->id;
    }
    
    public function setName($name) {
        $this->name = $name;
        return $this;
    }
    
    public function getName() {
        return $this->name;
    }
}
```

Afterwards you are able to use the created entity as if you were using a database.
Let's assume we have used the value ```http://www.yourSite.com/api/products``` for the product entity's ```@Table``` annotation.

```php
<?php

namespace CircleBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\HttpFoundation\Response;

class UserController extends Controller {

    /**
     * Sends the following request to the API:
     * POST http://www.yourSite.com/api/products HTTP/1.1
     * {"name": "Circle"}
     *
     * Let's assume the API responded with:
     * HTTP/1.1 200 OK
     * {"id": 1, "name": "Circle"}
     *
     * Response body is "1"
     */
    public function createAction() {
        $em     = $this->getDoctrine()->getManager();
        $entity = new CircleBundle\Entity\Product();
        $entity->setName('Circle');
        $em->persist($entity);
        $em->flush();
        
        return new Response($entity->getId());
    }
    
    /**
     * Sends the following request to the API by default:
     * GET http://www.yourSite.com/api/products/1 HTTP/1.1
     *
     * which might respond with:
     * HTTP/1.1 200 OK
     * {"id": 1, "name": "Circle"}
     *
     * Response body is "Circle"
     */
    public function readAction($id = 1) {
        $em     = $this->getDoctrine()->getManager();
        $entity = $em->find('CircleBundle\Entity\Product', $id);
        
        return new Response($entity->getName());
    }
    
    /**
     * Sends the following request to the API:
     * GET http://www.yourSite.com/api/products HTTP/1.1
     *
     * Example response:
     * HTTP/1.1 200 OK
     * [{"id": 1, "name": "Circle"}]
     *
     * Response body is "Circle"
     */
    public function readAllAction() {
        $em       = $this->getDoctrine()->getManager();
        $entities = $em->getRepository('CircleBundle\Entity\Product')->findAll();
        
        return new Response($entities->first()->getName());
    }
    
    /**
     * After sending a GET request (readAction) it sends the following 
     * request to the API by default:
     * PUT http://www.yourSite.com/api/products/1 HTTP/1.1
     * {"name": "myName"}
     *
     * Let's assume the API responded the GET request with:
     * HTTP/1.1 200 OK
     * {"id": 1, "name": "Circle"}
     *
     * and the PUT request with:
     * HTTP/1.1 200 OK
     * {"id": 1, "name": "myName"}
     *
     * Then the response body is "myName"
     */
    public function updateAction($id = 1) {
        $em     = $this->getDoctrine()->getManager();
        $entity = $em->find('CircleBundle\Entity\Product', $id);
        $entity->setName('myName');
        $em->flush();
        
        return new Response($entity->getName());
    }
    
    /**
     * After sending a GET request (readAction) it sends the following 
     * request to the API by default:
     * DELETE http://www.yourSite.com/api/products/1 HTTP/1.1
     *
     * If the response is:
     * HTTP/1.1 204 No Content
     *
     * the response body is ""
     */
    public function deleteAction($id = 1) {
        $em     = $this->getDoctrine()->getManager();
        $entity = $em->find('CircleBundle\Entity\Product', $id);
        $em->remove($entity);
        $em->flush();
        
        return new Response();
    }
}
```

## Specific routes for specific methods

Many REST APIs don't follow these conventions. Twitter, for example, uses different routes for several methods of the same entity:
```
POST friendships/create
GET  friendships/show
```

To use these APIs, too, you can adapt the ```rest_driver_routing.yml``` file, referenced in your driver config.

```
routes:
    products:
        post: "friendships/create"
        get:  "friendships/show"
```

*Important: These routes will only be used if the @table annotation is equal to the second node (in our example the second node is "products")!*

#Examples

Need some more examples? Here they are:

## Persisting entities
Imagine you have a REST API at http://www.your-url.com/api:

| Route | Method | Description | Payload | Response | Success HTTP Code | Error HTTP Code |
| ------------- |:-------------:| -----:|-----:|-----:|-----:|-----:|
| /addresses | POST | persists addresses | UnregisteredAddress | RegisteredAddress | 200 | 400 |


```c2hs
typedef UnregisteredAddress {
    street: String,
    city:   String
}

typedef RegisteredAddress {
    id:     Int,
    street: String,
    city:   String
}
```

Let's first configure Doctrine:

```yml
doctrine:
  dbal:
    driver_class: "Circle\\DoctrineRestDriver\\Driver"
    host:         "http://www.your-url.com/api"
    port:         "80"
    user:         ""
    password:     ""
```

Afterwards let's build the address entity:

```php
<?php
namespace CircleBundle\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * @ORM\Entity()
 * @ORM\Table("addresses") // or "http://www.your-url.com/api/addresses"
 */
class Address {

    /**
     * @ORM\Column(type="integer")
     * @ORM\Id
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    private $id;
    
    /**
     * @ORM\Column(type="string")
     */
    private $street;
    
    /**
     * @ORM\Column(type="string")
     */
    private $city;
    
    public function setStreet($street) {
        $this->street = $street;
        return $this;
    }
    
    public function getStreet() {
        return $this->street;
    }
    
    public function setCity($city) {
        $this->city = $city;
        return $this;
    }
    
    public function getCity() {
        return $this->city;
    }
    
    public function getId() {
        return $this->id;
    }
}
```

And finally the controller and its action:

```php
<?php

namespace CircleBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\HttpFoundation\Response;

class AddressController extends Controller {

    public function createAction($street, $city) {
        $em      = $this->getDoctrine()->getManager();
        $address = new CircleBundle\Address();
        
        $address->setStreet($street)->setCity($city);
        $em->persist($address);
        
        try {
            $em->flush();
            return new Response('successfully registered');
        } catch(RequestFailedException) {
            return new Response('invalid address');
        }
    }
}
```

That's it. Each time the createAction is called it will send a POST request to the API.

## Associating entities

Let's extend the first example. Now we want to add a new entity type ```User``` which references the addresses defined in the previous example.

The REST API offers the following additional routes:

| Route | Method | Description | Payload | Response |
| ------------- |:-------------:| -----:|-----:|-----:|
| /users | POST | persists a new user | UnregisteredUser | RegisteredUser |
| /addresses | POST | persists a new address | UnregisteredAddress | RegisteredAddress |
| /addresses/\<id\> | GET | returns one address | NULL | RegisteredAddress |

```c2hs
typedef UnregisteredUser {
    name:     String,
    password: String,
    address:  Index
}

typedef RegisteredUser {
    id:       Int,
    name:     String,
    password: String,
    address:  Index
}
```

First, we need to build an additional entity "User":

```php
namespace Circle\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * @ORM\Entity()
 * @ORM\Table("users") // or "http://www.your-url.com/api/users"
 */
class User {

    /**
     * @ORM\Column(type="integer")
     * @ORM\Id
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    private $id;
    
    /**
     * @ORM\Column(type="string")
     */
    private $name;
    
    /**
     * @ORM\OneToOne(targetEntity="CircleBundle\Address", cascade={"persist, remove"})
     */
    private $address;
    
    /**
     * @ORM\Column(type="string")
     */
    private $password;
    
    public function setName($name) {
        $this->name = $name;
        return $this;
    }
    
    public function getName() {
        return $this->name;
    }
    
    public function setPassword($password) {
        $this->password = $password;
        return $this;
    }
    
    public function getPassword() {
        return $this->password;
    }
    
    public function getId() {
        return $this->id;
    }
    
    public function setAddress(Address $address) {
        $this->address = $address;
        return $this;
    }
    
    public function getAddress() {
        return $this->address;
    }
}
```

The user has a relation to address. So let's have a look at what happens if we associate them:


```php
<?php

namespace CircleBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\HttpFoundation\Response;

class UserController extends Controller {

    public function createAction($name, $password, $addressId) {
        $em      = $this->getDoctrine()->getManager();
        $address = $em->find("CircleBundle\Entity\Address", $addressId);
        $user    = new User();
        
        $user->setName($name)
            ->setPassword($password)
            ->setAddress($address);
        
        $em->persist($user);
        $em->flush();
        
        return new Response('successfully registered');
    }
}
```

If we'd set name to ```username```, password to ```secretPassword``` and addressId to ```1``` by triggering the createAction, the following requests would be sent by our driver:

```
GET  http://www.your-url.com/api/addresses/1 HTTP/1.1
POST http://www.your-url.com/api/users HTTP/1.1 {"name": "username", "password":"secretPassword", "address":1}
```

Because we have used the option ```cascade={"remove"}``` on the relation between users and addresses DELETE requests for addresses are automatically sent if the owning user is removed:

```php
<?php

namespace CircleBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\HttpFoundation\Response;

class UserController extends Controller {
    
    public function remove($id = 1) {
        $em = $this->getDoctrine()->getManager();
        $em->find('CircleBundle\Entity\User', $id);
        $em->remove($em);
        $em->flush();
        
        return new Response('successfully removed');
    }
}
```


For example, a DELETE request with the id ```1``` would trigger these requests:
```
DELETE http://www.your-url.com/api/addresses/1 HTTP/1.1
DELETE http://www.your-url.com/api/users/1 HTTP/1.1
```


Great, isn't it?

## Using multiple Backends
In this last example we split the user and the address routes into two different REST APIs.
This means we need multiple managers which is explained in the Doctrine documentation:

```yml
doctrine:
  dbal:
    default_connection: default
    connections:
      default:
        driver:   "pdo_mysql"
        host:     "localhost"
        port:     3306
        user:     "root"
        password: "root"
      user_api:
        driver_class: "Circle\\DoctrineRestDriver\\Driver"
        host:         "http://api.user.your-url.com"
        port:         80
        user:         "Circle"
        password:     "CircleUsers"
        options:
          authentication_class:  "HttpAuthentication"
      address_api:
        driver_class: "Circle\\DoctrineRestDriver\\Driver"
        host:         "http://api.address.your-url.com"
        port:         80
        user:         "Circle"
        password:     "CircleAddresses"
        options:
          authentication_class:  "HttpAuthentication"
```

Now it's getting crazy: We will try to read data from two different APIs and persist them into a MySQL database.
Imagine the user API with the following route:

| Route | Method | Description | Payload | Response |
| ------------- |:-------------:| -----:|-----:|-----:|
| /users/\<id\> | GET | returns one user | NULL | RegisteredUser |

and the address API with this entry point:

| Route | Method | Description | Payload | Response |
| ------------- |:-------------:| -----:|-----:|-----:|
| /addresses/\<id\> | GET | returns one address | NULL | RegisteredAddress |

We want to read a user from the user API and an address from the address API.
After that we will associate and persist them in our MySQL database.

```php
<?php

namespace CircleBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\HttpFoundation\Response;

class UserController extends Controller {

    public function createAction($userId, $addressId) {
        $emUsers       = $this->getDoctrine()->getManager('user_api');
        $emAddresses   = $this->getDoctrine()->getManager('address_api');
        $emPersistence = $this->getDoctrine()->getManager();
        
        $user    = $emUsers->find("CircleBundle\Entity\User", $userId);
        $address = $emAddresses->find("CircleBundle\Entity\Address", $addressId);
        $user->setAddress($address);
        
        $emPersistence->persist($address);
        $emPersistence->persist($user);
        $emPersistence->flush();
        
        return new Response('successfully persisted');
    }
}
```

As you can see in the request log both APIs are requested:

```
GET  http://api.users.your-url.com/users/1 HTTP/1.1
GET  http://api.addresses.your-url.com/addresses/1 HTTP/1.1
```

Afterwards both entities are persisted in the default MySQL database.

#Testing

To test the bundle just type:

```
make test
```

#Contributing
If you want to contribute to this repository, please ensure ...
  - to follow the existing coding style.
  - to use the linting tools that are listed in the ```composer.json``` (which you get for free when using ```make```).
  - to add and/or customize unit tests for any changed code.
  - to reference the corresponding issue in your pull request with a small description of your changes.

All contributors are listed in the ```AUTHORS``` file, sorted by the time of their first contribution.
