<?php

namespace AlexDpy\AclBundle\Manager;

use AlexDpy\AclBundle\Exception\OidTypeException;
use AlexDpy\AclBundle\Exception\UnresolvedMaskException;
use Symfony\Component\Security\Acl\Domain\ObjectIdentity;
use Symfony\Component\Security\Acl\Domain\RoleSecurityIdentity;
use Symfony\Component\Security\Acl\Domain\UserSecurityIdentity;
use Symfony\Component\Security\Acl\Exception\AclNotFoundException;
use Symfony\Component\Security\Acl\Model\AclInterface;
use Symfony\Component\Security\Acl\Model\MutableAclInterface;
use Symfony\Component\Security\Acl\Model\MutableAclProviderInterface;
use Symfony\Component\Security\Acl\Model\ObjectIdentityInterface;
use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;
use Symfony\Component\Security\Acl\Permission\PermissionMapInterface;
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
     * @var PermissionMapInterface
     */
    protected $permissionMap;

    /**
     * @param PermissionMapInterface      $permissionMap
     * @param TokenStorageInterface       $tokenStorage
     * @param MutableAclProviderInterface $aclProvider
     */
    public function __construct(
        PermissionMapInterface $permissionMap,
        TokenStorageInterface $tokenStorage,
        MutableAclProviderInterface $aclProvider
    ) {
        $this->permissionMap = $permissionMap;
        $this->tokenStorage = $tokenStorage;
        $this->aclProvider = $aclProvider;
    }

    /**
     * {@inheritdoc}
     */
    public function grantRoleOnClass($permissions, $class, $role, $field = null)
    {
        $this->insertAces(
            $this->findOrCreateAcl($this->$aclManager->getObjectIdentity(AclIdentifierInterface::OID_TYPE_CLASS, $class)),
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
        $this->insertAces(
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
        $this->insertAces(
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
        $this->insertAces(
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
            $this->deleteAces($acl, $this->getRoleSecurityIdentity($role), $permissions, AclIdentifierInterface::OID_TYPE_CLASS, $field);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function revokeRoleOnObject($permissions, $object, $role, $field = null)
    {
        if (null !== $acl = $this->findAcl($this->getObjectIdentity(AclIdentifierInterface::OID_TYPE_OBJECT, $object))) {
            $this->deleteAces($acl, $this->getRoleSecurityIdentity($role), $permissions, AclIdentifierInterface::OID_TYPE_OBJECT, $field);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function revokeUserOnClass($permissions, $class, UserInterface $user = null, $field = null)
    {
        if (null !== $acl = $this->findAcl($this->getObjectIdentity(AclIdentifierInterface::OID_TYPE_CLASS, $class))) {
            $this->deleteAces($acl, $this->getUserSecurityIdentity($user), $permissions, AclIdentifierInterface::OID_TYPE_CLASS, $field);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function revokeUserOnObject($permissions, $object, UserInterface $user = null, $field = null)
    {
        if (null !== $acl = $this->findAcl($this->getObjectIdentity(AclIdentifierInterface::OID_TYPE_OBJECT, $object))) {
            $this->deleteAces($acl, $this->getUserSecurityIdentity($user), $permissions, AclIdentifierInterface::OID_TYPE_OBJECT, $field);
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
    protected function insertAces(MutableAclInterface $acl, SecurityIdentityInterface $securityIdentity, $permissions, $type, $field = null)
    {
        $permissions = (array) $permissions;
        foreach ($permissions as $permission) {
            $mask = min($this->resolveMasks($permission));

            if (!$this->hasAce($acl, $securityIdentity, $mask, $type, $field)) {
                if (null === $field) {
                    $acl->{'insert' . ucfirst($type) . 'Ace'}($securityIdentity, $mask);
                } else {
                    $acl->{'insert' . ucfirst($type) . 'FieldAce'}($field, $securityIdentity, $mask);
                }
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
    protected function deleteAces(MutableAclInterface $acl, SecurityIdentityInterface $securityIdentity, $permissions, $type, $field = null)
    {
        $type = ucfirst($type);
        $getMethod = null === $field ? 'get' . $type . 'Aces' : 'get' . $type . 'FieldAces';
        $deleteMethod = null === $field ? 'delete' . $type . 'Ace' : 'delete' . $type . 'FieldAce';

        $permissions = (array) $permissions;
        foreach ($permissions as $permission) {
            $masks = $this->resolveMasks($permission);

            foreach ($acl->{$getMethod}($field) as $index => $ace) {
                if ($securityIdentity->equals($ace->getSecurityIdentity()) && in_array($ace->getMask(), $masks)) {
                    $acl->{$deleteMethod}($index, $field);
                }
            }
        }

        $this->aclProvider->updateAcl($acl);
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

    /**
     * @param string      $permission
     * @param null|object $object
     *
     * @return int[]
     * @throws UnresolvedMaskException When the permissionMap does not contain the permission or does not support the permission/object combination
     */
    protected function resolveMasks($permission, $object = null)
    {
        if (!$this->permissionMap->contains($permission)) {
            throw UnresolvedMaskException::nonExistentPermission($permission);
        }

        if (null === $masks = $this->permissionMap->getMasks($permission, $object)) {
            throw UnresolvedMaskException::nonSupportedPermission($permission, $object);
        }

        return $masks;
    }

    /**
     * @param AclInterface              $acl
     * @param SecurityIdentityInterface $securityIdentity
     * @param int                       $mask
     * @param string                    $type
     * @param null|string               $field
     *
     * @return bool
     */
    protected function hasAce(AclInterface $acl, SecurityIdentityInterface $securityIdentity, $mask, $type, $field = null)
    {
        $type = ucfirst($type);
        $method = null === $field ? 'get' . $type . 'Aces' : 'get' . $type . 'FieldAces';

        foreach ($acl->{$method}($field) as $ace) {
            if ($mask === $ace->getMask() && $securityIdentity->equals($ace->getSecurityIdentity())) {
                return true;
            }
        }

        return false;
    }
}
