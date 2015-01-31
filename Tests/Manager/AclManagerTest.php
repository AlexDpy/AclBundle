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

    public function test_revoke_role_on_class()
    {
        $this->aclManager->grantRoleOnClass(['VIEW', 'EDIT', 'CREATE', 'DELETE'], $this->fooClass, self::ROLE_USER);
        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'VIEW', $this->fooClass));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'EDIT', $this->fooClass));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'CREATE', $this->fooClass));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'DELETE', $this->fooClass));

        $this->aclManager->revokeRoleOnClass('VIEW', $this->fooClass, self::ROLE_USER);
        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'VIEW', $this->fooClass));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'EDIT', $this->fooClass));

        $this->aclManager->revokeRoleOnClass('EDIT', $this->fooClass, self::ROLE_USER);
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'VIEW', $this->fooClass));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'EDIT', $this->fooClass));

        $this->aclManager->revokeRoleOnClass('CREATE', $this->fooClass, self::ROLE_USER);
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'CREATE', $this->fooClass));

        $this->aclManager->revokeRoleOnClass('DELETE', $this->fooClass, self::ROLE_USER);
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'DELETE', $this->fooClass));
    }

    public function test_revoke_role_on_class_with_field()
    {
        $this->aclManager->grantRoleOnClass(['VIEW', 'EDIT', 'CREATE', 'DELETE'], $this->fooClass, self::ROLE_USER, 'securedField');
        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'VIEW', $this->fooClass, 'securedField'));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'EDIT', $this->fooClass, 'securedField'));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'CREATE', $this->fooClass, 'securedField'));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'DELETE', $this->fooClass, 'securedField'));

        $this->aclManager->revokeRoleOnClass('VIEW', $this->fooClass, self::ROLE_USER, 'securedField');
        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'VIEW', $this->fooClass, 'securedField'));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'EDIT', $this->fooClass, 'securedField'));

        $this->aclManager->revokeRoleOnClass('EDIT', $this->fooClass, self::ROLE_USER, 'securedField');
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'VIEW', $this->fooClass, 'securedField'));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'EDIT', $this->fooClass, 'securedField'));

        $this->aclManager->revokeRoleOnClass('CREATE', $this->fooClass, self::ROLE_USER, 'securedField');
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'CREATE', $this->fooClass, 'securedField'));

        $this->aclManager->revokeRoleOnClass('DELETE', $this->fooClass, self::ROLE_USER, 'securedField');
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'DELETE', $this->fooClass, 'securedField'));
    }

    public function test_revoke_role_on_object()
    {
        $fooObject = new FooObject(uniqid());

        $this->aclManager->grantRoleOnObject(['VIEW', 'EDIT', 'CREATE', 'DELETE'], $fooObject, self::ROLE_USER);
        $this->assertTrue($this->aclChecker->roleIsGrantedOnObject(self::ROLE_USER, 'VIEW', $fooObject));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnObject(self::ROLE_USER, 'EDIT', $fooObject));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnObject(self::ROLE_USER, 'CREATE', $fooObject));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnObject(self::ROLE_USER, 'DELETE', $fooObject));

        $this->aclManager->revokeRoleOnObject('VIEW', $fooObject, self::ROLE_USER);
        $this->assertTrue($this->aclChecker->roleIsGrantedOnObject(self::ROLE_USER, 'VIEW', $fooObject));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnObject(self::ROLE_USER, 'EDIT', $fooObject));

        $this->aclManager->revokeRoleOnObject('EDIT', $fooObject, self::ROLE_USER);
        $this->assertFalse($this->aclChecker->roleIsGrantedOnObject(self::ROLE_USER, 'VIEW', $fooObject));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnObject(self::ROLE_USER, 'EDIT', $fooObject));

        $this->aclManager->revokeRoleOnObject('CREATE', $fooObject, self::ROLE_USER);
        $this->assertFalse($this->aclChecker->roleIsGrantedOnObject(self::ROLE_USER, 'CREATE', $fooObject));

        $this->aclManager->revokeRoleOnObject('DELETE', $fooObject, self::ROLE_USER);
        $this->assertFalse($this->aclChecker->roleIsGrantedOnObject(self::ROLE_USER, 'DELETE', $fooObject));
    }

    public function test_revoke_role_on_object_with_field()
    {
        $fooObject = new FooObject(uniqid());

        $this->aclManager->grantRoleOnObject(['VIEW', 'EDIT', 'CREATE', 'DELETE'], $fooObject, self::ROLE_USER, 'securedField');
        $this->assertTrue($this->aclChecker->roleIsGrantedOnObject(self::ROLE_USER, 'VIEW', $fooObject, 'securedField'));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnObject(self::ROLE_USER, 'EDIT', $fooObject, 'securedField'));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnObject(self::ROLE_USER, 'CREATE', $fooObject, 'securedField'));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnObject(self::ROLE_USER, 'DELETE', $fooObject, 'securedField'));

        $this->aclManager->revokeRoleOnObject('VIEW', $fooObject, self::ROLE_USER, 'securedField');
        $this->assertTrue($this->aclChecker->roleIsGrantedOnObject(self::ROLE_USER, 'VIEW', $fooObject, 'securedField'));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnObject(self::ROLE_USER, 'EDIT', $fooObject, 'securedField'));

        $this->aclManager->revokeRoleOnObject('EDIT', $fooObject, self::ROLE_USER, 'securedField');
        $this->assertFalse($this->aclChecker->roleIsGrantedOnObject(self::ROLE_USER, 'VIEW', $fooObject, 'securedField'));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnObject(self::ROLE_USER, 'EDIT', $fooObject, 'securedField'));

        $this->aclManager->revokeRoleOnObject('CREATE', $fooObject, self::ROLE_USER, 'securedField');
        $this->assertFalse($this->aclChecker->roleIsGrantedOnObject(self::ROLE_USER, 'CREATE', $fooObject, 'securedField'));

        $this->aclManager->revokeRoleOnObject('DELETE', $fooObject, self::ROLE_USER, 'securedField');
        $this->assertFalse($this->aclChecker->roleIsGrantedOnObject(self::ROLE_USER, 'DELETE', $fooObject, 'securedField'));
    }

    public function test_revoke_user_on_class()
    {
        $alice = $this->generateUser('alice');

        $this->aclManager->grantUserOnClass(['VIEW', 'EDIT', 'CREATE', 'DELETE'], $this->fooClass, $alice);
        $this->assertTrue($this->aclChecker->userIsGrantedOnClass($alice, 'VIEW', $this->fooClass));
        $this->assertTrue($this->aclChecker->userIsGrantedOnClass($alice, 'EDIT', $this->fooClass));
        $this->assertTrue($this->aclChecker->userIsGrantedOnClass($alice, 'CREATE', $this->fooClass));
        $this->assertTrue($this->aclChecker->userIsGrantedOnClass($alice, 'DELETE', $this->fooClass));

        $this->aclManager->revokeUserOnClass('VIEW', $this->fooClass, $alice);
        $this->assertTrue($this->aclChecker->userIsGrantedOnClass($alice, 'VIEW', $this->fooClass));
        $this->assertTrue($this->aclChecker->userIsGrantedOnClass($alice, 'EDIT', $this->fooClass));

        $this->aclManager->revokeUserOnClass('EDIT', $this->fooClass, $alice);
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($alice, 'VIEW', $this->fooClass));
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($alice, 'EDIT', $this->fooClass));

        $this->aclManager->revokeUserOnClass('CREATE', $this->fooClass, $alice);
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($alice, 'CREATE', $this->fooClass));

        $this->aclManager->revokeUserOnClass('DELETE', $this->fooClass, $alice);
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($alice, 'DELETE', $this->fooClass));
    }

    public function test_revoke_user_on_class_with_field()
    {
        $alice = $this->generateUser('alice');

        $this->aclManager->grantUserOnClass(['VIEW', 'EDIT', 'CREATE', 'DELETE'], $this->fooClass, $alice, 'securedField');
        $this->assertTrue($this->aclChecker->userIsGrantedOnClass($alice, 'VIEW', $this->fooClass, 'securedField'));
        $this->assertTrue($this->aclChecker->userIsGrantedOnClass($alice, 'EDIT', $this->fooClass, 'securedField'));
        $this->assertTrue($this->aclChecker->userIsGrantedOnClass($alice, 'CREATE', $this->fooClass, 'securedField'));
        $this->assertTrue($this->aclChecker->userIsGrantedOnClass($alice, 'DELETE', $this->fooClass, 'securedField'));

        $this->aclManager->revokeUserOnClass('VIEW', $this->fooClass, $alice, 'securedField');
        $this->assertTrue($this->aclChecker->userIsGrantedOnClass($alice, 'VIEW', $this->fooClass, 'securedField'));
        $this->assertTrue($this->aclChecker->userIsGrantedOnClass($alice, 'EDIT', $this->fooClass, 'securedField'));

        $this->aclManager->revokeUserOnClass('EDIT', $this->fooClass, $alice, 'securedField');
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($alice, 'VIEW', $this->fooClass, 'securedField'));
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($alice, 'EDIT', $this->fooClass, 'securedField'));

        $this->aclManager->revokeUserOnClass('CREATE', $this->fooClass, $alice, 'securedField');
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($alice, 'CREATE', $this->fooClass, 'securedField'));

        $this->aclManager->revokeUserOnClass('DELETE', $this->fooClass, $alice, 'securedField');
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($alice, 'DELETE', $this->fooClass, 'securedField'));
    }

    public function test_revoke_user_on_object()
    {
        $alice = $this->generateUser('alice');
        $fooObject = new FooObject(uniqid());

        $this->aclManager->grantUserOnObject(['VIEW', 'EDIT', 'CREATE', 'DELETE'], $fooObject, $alice);
        $this->assertTrue($this->aclChecker->userIsGrantedOnObject($alice, 'VIEW', $fooObject));
        $this->assertTrue($this->aclChecker->userIsGrantedOnObject($alice, 'EDIT', $fooObject));
        $this->assertTrue($this->aclChecker->userIsGrantedOnObject($alice, 'CREATE', $fooObject));
        $this->assertTrue($this->aclChecker->userIsGrantedOnObject($alice, 'DELETE', $fooObject));

        $this->aclManager->revokeUserOnObject('VIEW', $fooObject, $alice);
        $this->assertTrue($this->aclChecker->userIsGrantedOnObject($alice, 'VIEW', $fooObject));
        $this->assertTrue($this->aclChecker->userIsGrantedOnObject($alice, 'EDIT', $fooObject));

        $this->aclManager->revokeUserOnObject('EDIT', $fooObject, $alice);
        $this->assertFalse($this->aclChecker->userIsGrantedOnObject($alice, 'VIEW', $fooObject));
        $this->assertFalse($this->aclChecker->userIsGrantedOnObject($alice, 'EDIT', $fooObject));

        $this->aclManager->revokeUserOnObject('CREATE', $fooObject, $alice);
        $this->assertFalse($this->aclChecker->userIsGrantedOnObject($alice, 'CREATE', $fooObject));

        $this->aclManager->revokeUserOnObject('DELETE', $fooObject, $alice);
        $this->assertFalse($this->aclChecker->userIsGrantedOnObject($alice, 'DELETE', $fooObject));
    }

    public function test_revoke_user_on_object_with_field()
    {
        $alice = $this->generateUser('alice');
        $fooObject = new FooObject(uniqid());

        $this->aclManager->grantUserOnObject(['VIEW', 'EDIT', 'CREATE', 'DELETE'], $fooObject, $alice, 'securedField');
        $this->assertTrue($this->aclChecker->userIsGrantedOnObject($alice, 'VIEW', $fooObject, 'securedField'));
        $this->assertTrue($this->aclChecker->userIsGrantedOnObject($alice, 'EDIT', $fooObject, 'securedField'));
        $this->assertTrue($this->aclChecker->userIsGrantedOnObject($alice, 'CREATE', $fooObject, 'securedField'));
        $this->assertTrue($this->aclChecker->userIsGrantedOnObject($alice, 'DELETE', $fooObject, 'securedField'));

        $this->aclManager->revokeUserOnObject('VIEW', $fooObject, $alice, 'securedField');
        $this->assertTrue($this->aclChecker->userIsGrantedOnObject($alice, 'VIEW', $fooObject, 'securedField'));
        $this->assertTrue($this->aclChecker->userIsGrantedOnObject($alice, 'EDIT', $fooObject, 'securedField'));

        $this->aclManager->revokeUserOnObject('EDIT', $fooObject, $alice, 'securedField');
        $this->assertFalse($this->aclChecker->userIsGrantedOnObject($alice, 'VIEW', $fooObject, 'securedField'));
        $this->assertFalse($this->aclChecker->userIsGrantedOnObject($alice, 'EDIT', $fooObject, 'securedField'));

        $this->aclManager->revokeUserOnObject('CREATE', $fooObject, $alice, 'securedField');
        $this->assertFalse($this->aclChecker->userIsGrantedOnObject($alice, 'CREATE', $fooObject, 'securedField'));

        $this->aclManager->revokeUserOnObject('DELETE', $fooObject, $alice, 'securedField');
        $this->assertFalse($this->aclChecker->userIsGrantedOnObject($alice, 'DELETE', $fooObject, 'securedField'));
    }
}
