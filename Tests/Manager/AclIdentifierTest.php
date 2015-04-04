<?php

namespace AlexDpy\AclBundle\AclManager\Tests\Manager;

use AlexDpy\AclBundle\Exception\OidTypeException;
use AlexDpy\AclBundle\Manager\AclIdentifierInterface;
use AlexDpy\AclBundle\Tests\Model\FooObject;
use AlexDpy\AclBundle\Tests\Security\AbstractSecurityTest;
use Symfony\Component\Security\Acl\Domain\ObjectIdentity;
use Symfony\Component\Security\Core\User\User;

class AclIdentifierTest extends AbstractSecurityTest
{
    public function testGetObjectIdentity()
    {
        $this->assertInstanceOf(
            'Symfony\Component\Security\Acl\Model\ObjectIdentityInterface',
            $this->aclIdentifier->getObjectIdentity(
                AclIdentifierInterface::OID_TYPE_CLASS,
                'FooBar'
            )
        );

        $this->assertInstanceOf(
            'Symfony\Component\Security\Acl\Model\ObjectIdentityInterface',
            $this->aclIdentifier->getObjectIdentity(
                AclIdentifierInterface::OID_TYPE_CLASS,
                new FooObject(1)
            )
        );

        $this->assertInstanceOf(
            'Symfony\Component\Security\Acl\Model\ObjectIdentityInterface',
            $this->aclIdentifier->getObjectIdentity(
                AclIdentifierInterface::OID_TYPE_OBJECT,
                new FooObject(1)
            )
        );

        $this->assertInstanceOf(
            'Symfony\Component\Security\Acl\Model\ObjectIdentityInterface',
            $this->aclIdentifier->getObjectIdentity(
                'thistypedoesnotexist',
                new ObjectIdentity('class', 'Foo')
            )
        );

        try {
            $this->aclIdentifier->getObjectIdentity('thistypedoesnotexist', 'FooBar');
            $this->fail();
        } catch (OidTypeException $e) {
            $this->assertTrue(true);
        }
    }

    public function testGetUserSecurityIdentity()
    {
        $alice = $this->generateUser('alice');

        $this->assertInstanceOf(
            'Symfony\Component\Security\Acl\Domain\UserSecurityIdentity',
            $this->aclIdentifier->getUserSecurityIdentity($alice)
        );

        $this->authenticateUser($alice);

        $this->assertInstanceOf(
            'Symfony\Component\Security\Acl\Domain\UserSecurityIdentity',
            $this->aclIdentifier->getUserSecurityIdentity(null)
        );
    }

    public function testGetRoleSecurityIdentity()
    {
        $this->assertInstanceOf(
            'Symfony\Component\Security\Acl\Domain\RoleSecurityIdentity',
            $this->aclIdentifier->getRoleSecurityIdentity('ROLE_FOO')
        );
    }

    public function testUpdateUserSecurityIdentity()
    {
        $alice = $this->generateUser('alice');

        $this->aclManager->grantUserOnClass('VIEW', 'FooClass', $alice);
        $this->changeUsername($alice, 'alice2');

        $this->aclIdentifier->updateUserSecurityIdentity('alice', $alice);
        $this->assertEquals(1, (int) $this->connection->fetchColumn(
            'SELECT COUNT(id) FROM acl_security_identities WHERE username = 1 AND identifier = :identifier',
            ['identifier' => 'Symfony\Component\Security\Core\User\User-alice2']
        ));
    }

    public function testUpdateRoleSecurityIdentity()
    {
        $this->aclManager->grantRoleOnClass('VIEW', 'FooClass', 'ROLE_EDITOR');

        $this->aclIdentifier->updateRoleSecurityIdentity('ROLE_EDITOR', 'ROLE_EDITOR2');
        $this->assertEquals(1, (int) $this->connection->fetchColumn(
            'SELECT COUNT(id) FROM acl_security_identities WHERE username = 0 AND identifier = :identifier',
            ['identifier' => 'ROLE_EDITOR2']
        ));
    }

    /**
     * @param User $user
     * @param string $newUsername
     */
    private function changeUsername(User $user, $newUsername)
    {
        $reflection = new \ReflectionClass($user);
        $property = $reflection->getProperty('username');
        $property->setAccessible(true);
        $property->setValue($user, $newUsername);
    }
}
