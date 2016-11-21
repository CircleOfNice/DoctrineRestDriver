# Motivation
What does a black sheep and a white sheep have in common? They produce wool.<br />
What does a big bus and a small bus have in common? They drive people around.<br />
And what does a SQL database and a REST API have in common? They store data.<br />

As blatantly obvious as this sounds the consequences are tremendous: With REST APIs being nothing more than data storage backends, we are able to reuse object relational mapping tools to access them.

And because we have absolutely no idea how to write a programming language, we're tryin to do it like Rasmus and keep adding the next logical step on the way. So DoctrineRestDriver saw the light of day.

# Prerequisites

- You need composer to download the library

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
      format:               "json" | "YourOwnNamespaceName" | if not specified json will be used
      authenticator_class:  "HttpAuthentication" | "YourOwnNamespaceName" | if not specified no authentication will be used
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
      format:                         "json"
      authenticator_class:            "HttpAuthentication"
      CURLOPT_CURLOPT_FOLLOWLOCATION: true
      CURLOPT_HEADER:                 false
```

A full list of all possible options can be found here: http://php.net/manual/en/function.curl-setopt.php

# Usage

If your API routes follow these few conventions, using the driver is very easy:

- Each route must be structured the same: ```{apiHost}/{pathToApi}/{tableName}```
- The PUT, GET (single) and UPDATE routes need to contain an additional ```id```: ```{apiHost}/{pathToApi}/{tableName}/{id}```
- POST and GET (all) must follow the basic structure: ```{apiHost}/{pathToApi}/{tableName}```

Don't worry, if this is not the case: Luckily, we provide a few annotations for you to configure your own routes.


The examples below show how to use the driver in a Symfony environment.

## If your API follows our conventions

First of all create your entities:

```php
namespace CircleBundle\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * This annotation marks the class as managed entity:
 *
 * @ORM\Entity
 * @ORM\Table("products")
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

Afterwards, you are able to use the created entity as if you were using a database.

By using this setting, the driver is performing a lot of magic under the hood:

- It generally uses the request body to send data in JSON format
- It automatically maps the response into a valid entity if the status code matches the default expected status codes (200 for GET and PUT, 201 for POST 204 for DELETE)
- It saves the entity as managed doctrine entity
- It translates INSERT queries into POST requests to create new data
  - Urls have the following format: ```{apiHost}/{pathToApi}/{tableName}```
- UPDATE queries will be turned into PUT requests:
   - Urls have the following format: ```{apiHost}/{pathToApi}/{tableName}/{id}```
- The DELETE operation will remain:
  - Urls have the following format: ```{apiHost}/{pathToApi}/{tableName}/{id}```
- SELECT queries become GET requests:
  - Urls have the following format: ```{apiHost}/{pathToApi}/{tableName}/{id}``` (if a single entity is requested) or ```{apiHost}/{pathToApi}/{tableName}``` (if all entities are requested)

Let's watch the driver in action by implementing some controller methods. In this example we assume that we have configured the ```host``` setting [(chapter installation)](#installation) with ```http://www.yourSite.com/api```.

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
     * HTTP/1.1 201 Created
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

## If your API doesn't follow our conventions
Now it's time to introduce you to some annotations, which help you to configure your own routes. Be sure to use them only with ```Doctrine``` entities. All these annotations have the same structure so we will call them ```DataSource``` annotation:

```php
@DataSource\SomeName("http://www.myRoute.com", method="POST", statusCode=200)
```

The ```ROUTE``` value is mandatory, method and statusCode are optional.

To demonstrate their capabilities, let's customize some parts of the previous chapter with the ```DataSource``` annotation:

```php
namespace CircleBundle\Entity;

use Doctrine\ORM\Mapping as ORM;
use Circle\DoctrineRestDriver\Annotations as DataSource;

/**
 * This annotation marks the class as managed entity:
 *
 * @ORM\Entity
 * @ORM\Table("products")
 * @DataSource\Select("http://www.yourSite.com/api/products/findOne/{id}")
 * @DataSource\Fetch("http://www.yourSite.com/api/products/findAll")
 * @DataSource\Insert("http://www.yourSite.com/api/products/insert", statusCode=200)
 * @DataSource\Update("http://www.yourSite.com/api/products/update/{id}", method="POST")
 * @DataSource\Delete("http://www.yourSite.com/api/products/remove/{id}", method="POST", statusCode=200)
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

The annotations tell the driver to send the requests to the configured URLs for each custom configuration. If you just want to define a specific route for one method, you don't need to use all annotations provided. The ```{id}``` act as a placeholder for the entity's identifier.

```php
<?php

namespace CircleBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\HttpFoundation\Response;

class UserController extends Controller {

    /**
     * Sends the following request to the API:
     * POST http://www.yourSite.com/api/products/insert HTTP/1.1
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
     * GET http://www.yourSite.com/api/products/findOne/1 HTTP/1.1
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
     * GET http://www.yourSite.com/api/products/findAll HTTP/1.1
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
     * POST http://www.yourSite.com/api/products/update/1 HTTP/1.1
     * {"name": "myName"}
     *
     * Let's assume the API responded the GET request with:
     * HTTP/1.1 200 OK
     * {"id": 1, "name": "Circle"}
     *
     * and the POST request with:
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
     * POST http://www.yourSite.com/api/products/remove/1 HTTP/1.1
     *
     * If the response is:
     * HTTP/1.1 200 OK
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
 * @ORM\Table("addresses")
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
 * @ORM\Table("users")
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

#Jwt authentication
To use Jwt authentication you need to specify authenticator as JwtAuthentication

Jwt authentication specific options:
jwt_url: the url where the token can be retrieved from
user: jwt user
password: jwt_password
revalidate_token_time: specify how many seconds before the token expiers it should be revalidated. Defaults to 5.
jwt_prefix: To add a string before teh token. Defaults to empty string.
```yml
doctrine:
  dbal:
    driver_class: "Circle\\DoctrineRestDriver\\Driver"
    host:         "%default_api_url%"
    port:         "%default_api_port%"
    user:         "%default_api_username%"
    password:     "%default_api_password%"
    options:
      jwt_url:                  "%jwt_url%"
      authenticator_class:      "JwtAuthentication" 
      revalidate_token_time:    5
      jwt_prefix:               ""
```

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
