<?php

namespace AlexDpy\AclBundle\AclManager\Tests\Manager;

use AlexDpy\AclBundle\Tests\Model\FooObject;
use AlexDpy\AclBundle\Tests\Security\AbstractSecurityTest;
use Symfony\Component\Security\Acl\Dbal\AclProvider;
use Symfony\Component\Security\Acl\Dbal\MutableAclProvider;
use Symfony\Component\Security\Acl\Domain\Entry;
use Symfony\Component\Security\Acl\Domain\ObjectIdentity;
use Symfony\Component\Security\Acl\Domain\RoleSecurityIdentity;
use Symfony\Component\Security\Acl\Exception\ConcurrentModificationException;
use Symfony\Component\Security\Acl\Permission\MaskBuilder;
use Symfony\Component\Security\Acl\Permission\PermissionMapInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Authorization\AuthorizationChecker;
use Symfony\Component\Security\Csrf\TokenStorage\TokenStorageInterface;

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

    public function test_grant_on_class_then_grant_on_object()
    {
        $fooObject = new FooObject(uniqid());

        try {
            $this->aclManager->grantRoleOnClass('VIEW', $fooObject, self::ROLE_USER, 'securedField');
            $this->aclManager->grantRoleOnObject('VIEW', $fooObject, self::ROLE_USER, 'securedField');
        } catch (ConcurrentModificationException $e) {
            $this->fail();
        }
    }

    /*public function test_grant_on_object_then_grant_on_class()
    {
        $fooObject = new FooObject(uniqid());

        try {
            $this->aclManager->grantRoleOnObject('VIEW', $fooObject, self::ROLE_USER, 'securedField');
            $this->aclManager->grantRoleOnClass('VIEW', $fooObject, self::ROLE_USER, 'securedField');
        } catch (ConcurrentModificationException $e) {
            $this->fail();
        }
    }*/

    public function test_revoke_role()
    {
        $this->aclManager->grantRoleOnClass(['VIEW', 'EDIT', 'CREATE'], $this->fooClass, self::ROLE_USER);
        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'VIEW', $this->fooClass));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'EDIT', $this->fooClass));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'CREATE', $this->fooClass));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'DELETE', $this->fooClass));

        $this->aclManager->revokeRoleOnClass('VIEW', $this->fooClass, self::ROLE_USER);
        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'VIEW', $this->fooClass));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'EDIT', $this->fooClass));

        $this->aclManager->revokeRoleOnClass('EDIT', $this->fooClass, self::ROLE_USER);
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'VIEW', $this->fooClass));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'EDIT', $this->fooClass));

        $this->aclManager->revokeRoleOnClass('CREATE', $this->fooClass, self::ROLE_USER);
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'CREATE', $this->fooClass));

        $this->aclManager->grantRoleOnClass('DELETE', $this->fooClass, self::ROLE_USER);
        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'DELETE', $this->fooClass));

        $this->aclManager->revokeRoleOnClass('DELETE', $this->fooClass, self::ROLE_USER);
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'DELETE', $this->fooClass));
    }
}
