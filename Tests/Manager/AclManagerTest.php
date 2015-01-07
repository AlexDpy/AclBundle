<?php

namespace AlexDpy\AclBundle\AclManager\Tests\Manager;

use AlexDpy\AclBundle\Tests\Security\AbstractSecurityTest;
use AlexDpy\AclBundle\Tests\Model\BarObject;
use AlexDpy\AclBundle\Tests\Model\FooObject;

class AclManagerTest extends AbstractSecurityTest
{
    protected $fooClass;

    protected $barClass;

    public function setUp()
    {
        parent::setUp();
        $this->fooClass = 'AlexDpy\\AclBundle\\Tests\\Model\\FooObject';
        $this->barClass = 'AlexDpy\\AclBundle\\Tests\\Model\\BarObject';
    }

    public function tearDown()
    {
        parent::tearDown();
        $this->cleanDB();
    }

    public function test_is_granted_on_class_with_object()
    {
        $a = new FooObject(uniqid());
        $b = new BarObject(uniqid());

        $alice = $this->generateUser('alice');
        $bob = $this->generateUser('bob');
        $mallory = $this->generateUser('mallory');

        $this->aclManager->grantUserOnClass(['VIEW', 'EDIT'], $a, $alice);
        $this->aclManager->grantUserOnClass('MASTER', $b, $bob);

        $this->authenticateUser($alice);
        $this->assertTrue($this->aclChecker->isGrantedOnClass('VIEW', $a));
        $this->assertTrue($this->aclChecker->isGrantedOnClass('EDIT', $a));
        $this->assertTrue($this->aclChecker->isGrantedOnClass(['VIEW', 'EDIT'], $a));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('VIEW', $b));

        $this->authenticateUser($bob);
        $this->assertTrue($this->aclChecker->isGrantedOnClass('MASTER', $b));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('VIEW', $a));
        $this->assertTrue($this->aclChecker->isGrantedOnClass(['EDIT', 'VIEW', 'DELETE'], $b));

        $this->authenticateUser($mallory);
        $this->assertFalse($this->aclChecker->isGrantedOnClass('VIEW', $a));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('EDIT', $a));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('MASTER', $b));
    }

    public function test_is_granted_on_class_with_class()
    {
        $alice = $this->generateUser('alice');
        $bob = $this->generateUser('bob');
        $mallory = $this->generateUser('mallory');

        $this->aclManager->grantUserOnClass(['VIEW', 'EDIT'], $this->fooClass, $alice);
        $this->aclManager->grantUserOnClass('MASTER', $this->barClass, $bob);

        $this->authenticateUser($alice);
        $this->assertTrue($this->aclChecker->isGrantedOnClass('VIEW', $this->fooClass));
        $this->assertTrue($this->aclChecker->isGrantedOnClass('EDIT', $this->fooClass));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('VIEW', $this->barClass));
        $this->assertTrue($this->aclChecker->isGrantedOnClass(['VIEW', 'EDIT'], $this->fooClass));

        $this->authenticateUser($bob);
        $this->assertTrue($this->aclChecker->isGrantedOnClass('MASTER', $this->barClass));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('VIEW', $this->fooClass));
        $this->assertTrue($this->aclChecker->isGrantedOnClass(['EDIT', 'VIEW', 'DELETE'], $this->barClass));

        $this->authenticateUser($mallory);
        $this->assertFalse($this->aclChecker->isGrantedOnClass('VIEW', $this->fooClass));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('EDIT', $this->fooClass));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('MASTER', $this->barClass));
    }

    public function test_is_granted_field_on_class_with_object()
    {
        $a = new FooObject(uniqid());
        $b = new BarObject(uniqid());

        $alice = $this->generateUser('alice');
        $bob = $this->generateUser('bob');
        $mallory = $this->generateUser('mallory');

        $this->aclManager->grantUserOnClass(['VIEW', 'EDIT'], $a, $alice, 'securedField');
        $this->aclManager->grantUserOnClass('MASTER', $a, $bob, 'foo');
        $this->aclManager->grantUserOnClass('EDIT', $b, $bob, 'securedField');

        $this->authenticateUser($alice);
        $this->assertTrue($this->aclChecker->isGrantedOnClass('VIEW', $a, 'securedField'));
        $this->assertTrue($this->aclChecker->isGrantedOnClass('EDIT', $a, 'securedField'));
        $this->assertTrue($this->aclChecker->isGrantedOnClass(['VIEW', 'EDIT'], $a, 'securedField'));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('MASTER', $a, 'foo'));

        $this->authenticateUser($bob);
        $this->assertFalse($this->aclChecker->isGrantedOnClass('VIEW', $a, 'securedField'));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('EDIT', $a, 'securedField'));
        $this->assertFalse($this->aclChecker->isGrantedOnClass(['EDIT', 'VIEW'], $a, 'securedField'));

        $this->assertTrue($this->aclChecker->isGrantedOnClass('MASTER', $a, 'foo'));
        $this->assertTrue($this->aclChecker->isGrantedOnClass('EDIT', $b, 'securedField'));

        $this->authenticateUser($mallory);
        $this->assertFalse($this->aclChecker->isGrantedOnClass('VIEW', $a, 'securedField'));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('EDIT', $a, 'securedField'));
        $this->assertFalse($this->aclChecker->isGrantedOnClass(['EDIT', 'VIEW'], $a, 'securedField'));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('MASTER', $a, 'foo'));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('EDIT', $b, 'securedField'));
    }

    public function test_is_granted_field_on_class_with_class()
    {
        $alice = $this->generateUser('alice');
        $bob = $this->generateUser('bob');
        $mallory = $this->generateUser('mallory');

        $this->aclManager->grantUserOnClass(['VIEW', 'EDIT'], $this->fooClass, $alice, 'securedField');
        $this->aclManager->grantUserOnClass('MASTER', $this->fooClass, $bob, 'foo');
        $this->aclManager->grantUserOnClass('EDIT', $this->barClass, $bob, 'securedField');

        $this->authenticateUser($alice);
        $this->assertTrue($this->aclChecker->isGrantedOnClass('VIEW', $this->fooClass, 'securedField'));
        $this->assertTrue($this->aclChecker->isGrantedOnClass('EDIT', $this->fooClass, 'securedField'));
        $this->assertTrue($this->aclChecker->isGrantedOnClass(['VIEW', 'EDIT'], $this->fooClass, 'securedField'));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('MASTER', $this->fooClass, 'foo'));

        $this->authenticateUser($bob);
        $this->assertFalse($this->aclChecker->isGrantedOnClass('VIEW', $this->fooClass, 'securedField'));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('EDIT', $this->fooClass, 'securedField'));
        $this->assertFalse($this->aclChecker->isGrantedOnClass(['EDIT', 'VIEW'], $this->fooClass, 'securedField'));

        $this->assertTrue($this->aclChecker->isGrantedOnClass('MASTER', $this->fooClass, 'foo'));
        $this->assertTrue($this->aclChecker->isGrantedOnClass('EDIT', $this->barClass, 'securedField'));

        $this->authenticateUser($mallory);
        $this->assertFalse($this->aclChecker->isGrantedOnClass('VIEW', $this->fooClass, 'securedField'));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('EDIT', $this->fooClass, 'securedField'));
        $this->assertFalse($this->aclChecker->isGrantedOnClass(['EDIT', 'VIEW'], $this->fooClass, 'securedField'));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('MASTER', $this->fooClass, 'foo'));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('EDIT', $this->barClass, 'securedField'));
    }
}
