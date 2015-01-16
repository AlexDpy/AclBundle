<?php

namespace AlexDpy\AclBundle\AclManager\Tests\Manager;

use AlexDpy\AclBundle\Tests\Security\AbstractSecurityTest;

class AclManagerTest extends AbstractSecurityTest
{
    const ROLE_USER = 'ROLE_USER';
    const ROLE_ADMIN = 'ROLE_ADMIN';
    const ROLE_SUPER_ADMIN = 'ROLE_SUPER_ADMIN';

    protected $fooClass;
    protected $barClass;

    public function setUp()
    {
        parent::setUp();
        $this->fooClass = 'AlexDpy\AclBundle\Tests\Model\FooObject';
        $this->barClass = 'AlexDpy\AclBundle\Tests\Model\BarObject';
    }

    public function tearDown()
    {
        parent::tearDown();
        $this->cleanDB();
    }

    public function test_revoke_role_on_class()
    {
//        $this->aclManager->grantRoleOnClass(['VIEW', 'EDIT'], $this->fooClass, self::ROLE_USER);
//        $this->aclManager->grantRoleOnClass('MASTER', $this->barClass, self::ROLE_ADMIN);
//
//        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'VIEW', $this->fooClass));
//        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'EDIT', $this->fooClass));
//        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'VIEW', $this->barClass));
//        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, ['VIEW', 'EDIT'], $this->fooClass));
//
//        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_ADMIN, 'MASTER', $this->barClass));
//        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_ADMIN, 'VIEW', $this->fooClass));
//        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_ADMIN, ['EDIT', 'VIEW', 'DELETE'], $this->barClass));
//
//        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_SUPER_ADMIN, 'VIEW', $this->fooClass));
//        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_SUPER_ADMIN, 'EDIT', $this->fooClass));
//        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_SUPER_ADMIN, 'MASTER', $this->barClass));
    }
}
