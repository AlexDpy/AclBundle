<?php

namespace AlexDpy\AclBundle\Manager;

use AlexDpy\AclBundle\Exception\OidTypeException;
use Symfony\Component\Security\Acl\Domain\ObjectIdentity;
use Symfony\Component\Security\Acl\Domain\RoleSecurityIdentity;
use Symfony\Component\Security\Acl\Domain\UserSecurityIdentity;
use Symfony\Component\Security\Acl\Exception\AclNotFoundException;
use Symfony\Component\Security\Acl\Model\AclInterface;
use Symfony\Component\Security\Acl\Model\MutableAclInterface;
use Symfony\Component\Security\Acl\Model\MutableAclProviderInterface;
use Symfony\Component\Security\Acl\Model\ObjectIdentityInterface;
use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;
use Symfony\Component\Security\Acl\Permission\MaskBuilder;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Role\Role;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Util\ClassUtils;

class AclManager implements AclManagerInterface, AclIdentifierInterface
{
    /**
     * @var MutableAclProviderInterface $aclProvider
     */
    protected $aclProvider;

    /**
     * @var TokenStorageInterface $tokenStorage
     */
    protected $tokenStorage;

    /**
     * @param TokenStorageInterface       $tokenStorage
     * @param MutableAclProviderInterface $aclProvider
     */
    public function __construct(
        TokenStorageInterface $tokenStorage,
        MutableAclProviderInterface $aclProvider
    ) {
        $this->tokenStorage = $tokenStorage;
        $this->aclProvider = $aclProvider;
    }

    /**
     * {@inheritdoc}
     */
    public function grantRoleOnClass($permissions, $class, $role, $field = null)
    {
        $this->grant(
            $this->findOrCreateAcl($this->getObjectIdentity(AclIdentifierInterface::OID_TYPE_CLASS, $class)),
            $this->getRoleSecurityIdentity($role),
            $permissions,
            AclIdentifierInterface::OID_TYPE_CLASS,
            $field
        );
    }
    /**
     * {@inheritdoc}
     */
    public function grantRoleOnObject($permissions, $object, $role, $field = null)
    {
        $this->grant(
            $this->findOrCreateAcl($this->getObjectIdentity(AclIdentifierInterface::OID_TYPE_OBJECT, $object)),
            $this->getRoleSecurityIdentity($role),
            $permissions,
            AclIdentifierInterface::OID_TYPE_OBJECT,
            $field
        );
    }
    /**
     * {@inheritdoc}
     */
    public function grantUserOnClass($permissions, $class, UserInterface $user = null, $field = null)
    {
        $this->grant(
            $this->findOrCreateAcl($this->getObjectIdentity(AclIdentifierInterface::OID_TYPE_CLASS, $class)),
            $this->getUserSecurityIdentity($user),
            $permissions,
            AclIdentifierInterface::OID_TYPE_CLASS,
            $field
        );
    }
    /**
     * {@inheritdoc}
     */
    public function grantUserOnObject($permissions, $object, UserInterface $user = null, $field = null)
    {
        $this->grant(
            $this->findOrCreateAcl($this->getObjectIdentity(AclIdentifierInterface::OID_TYPE_OBJECT, $object)),
            $this->getUserSecurityIdentity($user),
            $permissions,
            AclIdentifierInterface::OID_TYPE_OBJECT,
            $field
        );
    }
    /**
     * {@inheritdoc}
     */
    public function revokeRoleOnClass($permissions, $class, $role, $field = null)
    {
        if (null !== $acl = $this->findAcl($this->getObjectIdentity(AclIdentifierInterface::OID_TYPE_CLASS, $class))) {
            $this->revoke($acl, $this->getRoleSecurityIdentity($role), $permissions, AclIdentifierInterface::OID_TYPE_CLASS, $field);
        }
    }
    /**
     * {@inheritdoc}
     */
    public function revokeRoleOnObject($permissions, $object, $role, $field = null)
    {
        if (null !== $acl = $this->findAcl($this->getObjectIdentity(AclIdentifierInterface::OID_TYPE_OBJECT, $object))) {
            $this->revoke($acl, $this->getRoleSecurityIdentity($role), $permissions, AclIdentifierInterface::OID_TYPE_OBJECT, $field);
        }
    }
    /**
     * {@inheritdoc}
     */
    public function revokeUserOnClass($permissions, $class, UserInterface $user = null, $field = null)
    {
        if (null !== $acl = $this->findAcl($this->getObjectIdentity(AclIdentifierInterface::OID_TYPE_CLASS, $class))) {
            $this->revoke($acl, $this->getUserSecurityIdentity($user), $permissions, AclIdentifierInterface::OID_TYPE_CLASS, $field);
        }
    }
    /**
     * {@inheritdoc}
     */
    public function revokeUserOnObject($permissions, $object, UserInterface $user = null, $field = null)
    {
        if (null !== $acl = $this->findAcl($this->getObjectIdentity(AclIdentifierInterface::OID_TYPE_OBJECT, $object))) {
            $this->revoke($acl, $this->getUserSecurityIdentity($user), $permissions, AclIdentifierInterface::OID_TYPE_OBJECT, $field);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function deleteAclForClass($class)
    {
        $this->aclProvider->deleteAcl($this->getObjectIdentity(AclIdentifierInterface::OID_TYPE_CLASS, $class));
    }

    /**
     * {@inheritdoc}
     */
    public function deleteAclForObject($object)
    {
        $this->aclProvider->deleteAcl($this->getObjectIdentity(AclIdentifierInterface::OID_TYPE_OBJECT, $object));
    }

    /**
     * {@inheritdoc}
     */
    public function getObjectIdentity($type, $classOrObject)
    {
        switch ($type) {
            case self::OID_TYPE_CLASS:
                if (is_object($classOrObject)) {
                    $classOrObject = ClassUtils::getRealClass($classOrObject);
                }

                return new ObjectIdentity($type, $classOrObject);
            case self::OID_TYPE_OBJECT:
                return ObjectIdentity::fromDomainObject($classOrObject);
        }

        throw new OidTypeException($type);
    }

    /**
     * @param MutableAclInterface       $acl
     * @param SecurityIdentityInterface $securityIdentity
     * @param string|string[]           $permissions
     * @param string                    $type
     * @param null|string               $field
     */
    protected function grant(MutableAclInterface $acl, SecurityIdentityInterface $securityIdentity, $permissions, $type, $field = null)
    {
        $index = false;
        $oldMask = 0;
        foreach ($acl->{$this->resolveAceMethod('get', $type, $field)}($field) as $k => $ace) {
            if ($securityIdentity->equals($ace->getSecurityIdentity())) {
                $index = $k;
                $oldMask = $ace->getMask();

                continue;
            }
        }

        $maskBuilder = new MaskBuilder($oldMask);

        foreach ((array) $permissions as $permission) {
            $maskBuilder->add($permission);
        }

        if (false === $index) {
            if (null === $field) {
                $acl->{$this->resolveAceMethod('insert', $type, $field)}($securityIdentity, $maskBuilder->get());
            } else {
                $acl->{$this->resolveAceMethod('insert', $type, $field)}($field, $securityIdentity, $maskBuilder->get());
            }
        } else {
            if (null === $field) {
                $acl->{$this->resolveAceMethod('update', $type, $field)}($index, $maskBuilder->get());
            } else {
                $acl->{$this->resolveAceMethod('update', $type, $field)}($index, $field, $maskBuilder->get());
            }
        }

        $this->aclProvider->updateAcl($acl);
    }

    /**
     * @param MutableAclInterface       $acl
     * @param SecurityIdentityInterface $securityIdentity
     * @param string|string[]           $permissions
     * @param string                    $type
     * @param null|string               $field
     */
    protected function revoke(MutableAclInterface $acl, SecurityIdentityInterface $securityIdentity, $permissions, $type, $field = null)
    {
        $index = false;
        $oldMask = 0;
        foreach ($acl->{$this->resolveAceMethod('get', $type, $field)}($field) as $k => $ace) {
            if ($securityIdentity->equals($ace->getSecurityIdentity())) {
                $index = $k;
                $oldMask = $ace->getMask();
                continue;
            }
        }

        if (false !== $index) {
            $maskBuilder = new MaskBuilder($oldMask);

            foreach ((array) $permissions as $permission) {
                $maskBuilder->remove($permission);
            }

            if (null === $field) {
                $acl->{$this->resolveAceMethod('update', $type, $field)}($index, $maskBuilder->get());
            } else {
                $acl->{$this->resolveAceMethod('update', $type, $field)}($index, $field, $maskBuilder->get());
            }
        }

        $this->aclProvider->updateAcl($acl);
    }

    /**
     * @param string      $method get|insert|update|delete
     * @param string      $type
     * @param null|string $field
     *
     * @return string
     */
    protected function resolveAceMethod($method, $type, $field = null)
    {
        $result = $method . ucfirst($type);

        if (null !== $field) {
            $result .= 'Field';
        }

        $result .= 'Ace';

        if ('get' === $method) {
            $result .= 's';
        }

        return $result;
    }

    /**
     * @param ObjectIdentityInterface $objectIdentity
     *
     * @return AclInterface|MutableAclInterface
     */
    protected function findOrCreateAcl(ObjectIdentityInterface $objectIdentity)
    {
        try {
            return $this->aclProvider->findAcl($objectIdentity);
        } catch (AclNotFoundException $e) {
            return $this->aclProvider->createAcl($objectIdentity);
        }
    }

    /**
     * @param ObjectIdentityInterface $objectIdentity
     *
     * @return null|AclInterface
     */
    protected function findAcl(ObjectIdentityInterface $objectIdentity)
    {
        try {
            return $this->aclProvider->findAcl($objectIdentity);
        } catch (AclNotFoundException $e) {
            return null;
        }
    }

    /**
     * @param null|UserInterface $user
     *
     * @return UserSecurityIdentity
     */
    protected function getUserSecurityIdentity(UserInterface $user = null)
    {
        return null === $user
            ? UserSecurityIdentity::fromToken($this->tokenStorage->getToken())
            : UserSecurityIdentity::fromAccount($user);
    }

    /**
     * @param string|Role $role a Role instance, or its string representation
     *
     * @return RoleSecurityIdentity
     */
    protected function getRoleSecurityIdentity($role)
    {
        return new RoleSecurityIdentity($role);
    }
}
