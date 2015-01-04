<?php

namespace AlexDpy\AclBundle\Manager;

use AlexDpy\AclBundle\Exception\AceTypeException;
use AlexDpy\AclBundle\Exception\UnresolvedMaskException;
use AlexDpy\AclBundle\Token\FakeRoleToken;
use AlexDpy\AclBundle\Token\FakeUserToken;
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
use Symfony\Component\Security\Acl\Voter\FieldVote;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManagerInterface;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Core\Role\Role;
use Symfony\Component\Security\Core\Role\RoleInterface;
use Symfony\Component\Security\Core\User\User;
use Symfony\Component\Security\Core\User\UserInterface;

class AclManager
{
    const ACE_TYPE_CLASS = 'class';
    const ACE_TYPE_OBJECT = 'object';

    /**
     * @var PermissionMapInterface
     */
    protected $permissionMap;

    /**
     * @var AuthorizationCheckerInterface $authorizationChecker
     */
    protected $authorizationChecker;

    /**
     * @var TokenStorageInterface $tokenStorage
     */
    protected $tokenStorage;

    /**
     * @var MutableAclProviderInterface $aclProvider
     */
    protected $aclProvider;

    /**
     * @var AccessDecisionManagerInterface $accessDecisionManager
     */
    protected $accessDecisionManager;

    /**
     * @param PermissionMapInterface         $permissionMap
     * @param AuthorizationCheckerInterface  $authorizationChecker
     * @param TokenStorageInterface          $tokenStorage
     * @param MutableAclProviderInterface    $aclProvider
     * @param AccessDecisionManagerInterface $accessDecisionManager
     */
    public function __construct(
        PermissionMapInterface $permissionMap,
        AuthorizationCheckerInterface $authorizationChecker,
        TokenStorageInterface $tokenStorage,
        MutableAclProviderInterface $aclProvider,
        AccessDecisionManagerInterface $accessDecisionManager
    ) {
        $this->permissionMap = $permissionMap;
        $this->authorizationChecker = $authorizationChecker;
        $this->tokenStorage = $tokenStorage;
        $this->aclProvider = $aclProvider;
        $this->accessDecisionManager = $accessDecisionManager;
    }

    /**
     * @param string|array       $attributes
     * @param null|string|object $classOrObject
     * @param null|string        $field
     *
     * @return bool
     */
    public function isGranted($attributes, $classOrObject = null, $field = null)
    {
        if (null === $classOrObject) {
            return $this->authorizationChecker->isGranted($attributes);
        } elseif (is_string($classOrObject)) {
            return $this->isGrantedOnClass($attributes, $classOrObject, $field);
        } elseif (is_object($classOrObject)) {
            return $this->isGrantedOnObject($attributes, $classOrObject, $field);
        }

        return false;
    }

    /**
     * @param string|array  $attributes
     * @param string|object $class
     * @param null|string   $field
     *
     * @return bool
     */
    public function isGrantedOnClass($attributes, $class, $field = null)
    {
        return $this->authorizationChecker->isGranted(
            $attributes,
            $this->getObjectToSecure(self::ACE_TYPE_CLASS, $class, $field)
        );
    }

    /**
     * @param string|array $attributes
     * @param object       $object
     * @param null|string  $field
     *
     * @return bool
     */
    public function isGrantedOnObject($attributes, $object, $field = null)
    {
        return $this->authorizationChecker->isGranted(
            $attributes,
            $this->getObjectToSecure(self::ACE_TYPE_OBJECT, $object, $field)
        );
    }

    /**
     * @param string|array|RoleInterface|TokenInterface $role
     * @param string|array                              $attributes
     * @param null|string|object                        $classOrObject
     * @param null|string                               $field
     *
     * @return bool
     */
    public function roleIsGranted($role, $attributes, $classOrObject = null, $field = null)
    {
        if (null === $classOrObject) {
            return $this->accessDecisionManager->decide($this->getRoleToken($role), (array) $attributes, $classOrObject);
        } elseif (is_string($classOrObject)) {
            return $this->roleIsGrantedOnClass($this->getRoleToken($role), $attributes, $classOrObject, $field);
        } elseif (is_object($classOrObject)) {
            return $this->roleIsGrantedOnObject($this->getRoleToken($role), $attributes, $classOrObject, $field);
        }

        return false;
    }

    /**
     * @param string|array|RoleInterface|TokenInterface $role
     * @param string|array                              $attributes
     * @param string|object                             $class
     * @param null|string                               $field
     *
     * @return bool
     */
    public function roleIsGrantedOnClass($role, $attributes, $class, $field = null)
    {
        return $this->accessDecisionManager->decide(
            $this->getRoleToken($role),
            (array) $attributes,
            $this->getObjectToSecure(self::ACE_TYPE_CLASS, $class, $field)
        );
    }

    /**
     * @param string|array|RoleInterface|TokenInterface $role
     * @param string|array                              $attributes
     * @param object                                    $object
     * @param null|string                               $field
     *
     * @return bool
     */
    public function roleIsGrantedOnObject($role, $attributes, $object, $field = null)
    {
        return $this->accessDecisionManager->decide(
            $this->getRoleToken($role),
            (array) $attributes,
            $this->getObjectToSecure(self::ACE_TYPE_OBJECT, $object, $field)
        );
    }

    /**
     * @param TokenInterface|UserInterface|string $user
     * @param string|array                        $attributes
     * @param null|string|object                  $classOrObject
     * @param null|string                         $field
     *
     * @return bool
     */
    public function userIsGranted($user, $attributes, $classOrObject = null, $field = null)
    {
        if (null === $classOrObject) {
            return $this->accessDecisionManager->decide($this->getUserToken($user), (array) $attributes, $classOrObject);
        } elseif (is_string($classOrObject)) {
            return $this->userIsGrantedOnClass($this->getUserToken($user), $attributes, $classOrObject, $field);
        } elseif (is_object($classOrObject)) {
            return $this->userIsGrantedOnObject($this->getUserToken($user), $attributes, $classOrObject, $field);
        }

        return false;
    }

    /**
     * @param TokenInterface|UserInterface|string $user
     * @param string|array                        $attributes
     * @param string|object                       $class
     * @param null|string                         $field
     *
     * @return bool
     */
    public function userIsGrantedOnClass($user, $attributes, $class, $field = null)
    {
        return $this->accessDecisionManager->decide(
            $this->getUserToken($user),
            (array) $attributes,
            $this->getObjectToSecure(self::ACE_TYPE_CLASS, $class, $field)
        );
    }

    /**
     * @param TokenInterface|UserInterface|string $user
     * @param string|array                        $attributes
     * @param object                              $object
     * @param null|string                         $field
     *
     * @return bool
     */
    public function userIsGrantedOnObject($user, $attributes, $object, $field = null)
    {
        return $this->accessDecisionManager->decide(
            $this->getUserToken($user),
            (array) $attributes,
            $this->getObjectToSecure(self::ACE_TYPE_OBJECT, $object, $field)
        );
    }

    /**
     * @param string|array  $permissions
     * @param string|object $class
     * @param string|Role   $role
     * @param null|string   $field
     */
    public function grantRoleOnClass($permissions, $class, $role, $field = null)
    {
        $this->insertAces(
            $this->findOrCreateAcl($this->getObjectIdentity(self::ACE_TYPE_CLASS, $class)),
            $this->getRoleSecurityIdentity($role),
            $permissions,
            self::ACE_TYPE_CLASS,
            $field
        );
    }

    /**
     * @param string|array $permissions
     * @param object       $object
     * @param string|Role  $role
     * @param null|string  $field
     */
    public function grantRoleOnObject($permissions, $object, $role, $field = null)
    {
        $this->insertAces(
            $this->findOrCreateAcl($this->getObjectIdentity(self::ACE_TYPE_OBJECT, $object)),
            $this->getRoleSecurityIdentity($role),
            $permissions,
            self::ACE_TYPE_OBJECT,
            $field
        );
    }

    /**
     * @param string|array       $permissions
     * @param string|object      $class
     * @param null|UserInterface $user
     * @param null|string        $field
     */
    public function grantUserOnClass($permissions, $class, UserInterface $user = null, $field = null)
    {
        $this->insertAces(
            $this->findOrCreateAcl($this->getObjectIdentity(self::ACE_TYPE_CLASS, $class)),
            $this->getUserSecurityIdentity($user),
            $permissions,
            self::ACE_TYPE_CLASS,
            $field
        );
    }

    /**
     * @param string|array       $permissions
     * @param object             $object
     * @param null|UserInterface $user
     * @param null|string        $field
     */
    public function grantUserOnObject($permissions, $object, UserInterface $user = null, $field = null)
    {
        $this->insertAces(
            $this->findOrCreateAcl($this->getObjectIdentity(self::ACE_TYPE_OBJECT, $object)),
            $this->getUserSecurityIdentity($user),
            $permissions,
            self::ACE_TYPE_OBJECT,
            $field
        );
    }

    /**
     * @param string|array  $permissions
     * @param string|object $class
     * @param string|Role   $role
     * @param null|string   $field
     */
    public function revokeRoleOnClass($permissions, $class, $role, $field = null)
    {
        if (null !== $acl = $this->findAcl($this->getObjectIdentity(self::ACE_TYPE_CLASS, $class))) {
            $this->deleteAces($acl, $this->getRoleSecurityIdentity($role), $permissions, self::ACE_TYPE_CLASS, $field);
        }
    }

    /**
     * @param string|array $permissions
     * @param object       $object
     * @param string|Role  $role
     * @param null|string  $field
     */
    public function revokeRoleOnObject($permissions, $object, $role, $field = null)
    {
        if (null !== $acl = $this->findAcl($this->getObjectIdentity(self::ACE_TYPE_OBJECT, $object))) {
            $this->deleteAces($acl, $this->getRoleSecurityIdentity($role), $permissions, self::ACE_TYPE_OBJECT, $field);
        }
    }

    /**
     * @param string|array       $permissions
     * @param string|object      $class
     * @param null|UserInterface $user
     * @param null|string        $field
     */
    public function revokeUserOnClass($permissions, $class, UserInterface $user = null, $field = null)
    {
        if (null !== $acl = $this->findAcl($this->getObjectIdentity(self::ACE_TYPE_CLASS, $class))) {
            $this->deleteAces($acl, $this->getUserSecurityIdentity($user), $permissions, self::ACE_TYPE_CLASS, $field);
        }
    }

    /**
     * @param string|array       $permissions
     * @param object             $object
     * @param null|UserInterface $user
     * @param null|string        $field
     */
    public function revokeUserOnObject($permissions, $object, UserInterface $user = null, $field = null)
    {
        if (null !== $acl = $this->findAcl($this->getObjectIdentity(self::ACE_TYPE_OBJECT, $object))) {
            $this->deleteAces($acl, $this->getUserSecurityIdentity($user), $permissions, self::ACE_TYPE_OBJECT, $field);
        }
    }

    /**
     * @param string|object $class
     */
    public function deleteAclForClass($class)
    {
        $this->aclProvider->deleteAcl($this->getObjectIdentity(self::ACE_TYPE_CLASS, $class));
    }

    /**
     * @param object $object
     */
    public function deleteAclForObject($object)
    {
        $this->aclProvider->deleteAcl($this->getObjectIdentity(self::ACE_TYPE_OBJECT, $object));
    }

    /**
     * @param MutableAclInterface       $acl
     * @param SecurityIdentityInterface $securityIdentity
     * @param string|array              $permissions
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
     * @param string|array              $permissions
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
     * @param string      $permission
     * @param null|object $object
     *
     * @return array
     * @throws UnresolvedMaskException
     */
    protected function resolveMasks($permission, $object = null)
    {
        $permission = strtoupper($permission);

        if (!$this->permissionMap->contains($permission)) {
            throw UnresolvedMaskException::nonExistentPermission($permission);
        }

        if (null === $masks = $this->permissionMap->getMasks($permission, $object)) {
            throw UnresolvedMaskException::nonSupportedPermission($permission, $object);
        }

        return $masks;
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
     * @param string|array|RoleInterface|TokenInterface $role
     *
     * @return FakeRoleToken|TokenInterface
     */
    protected function getRoleToken($role)
    {
        return $role instanceof TokenInterface ? $role :  new FakeRoleToken((array) $role);
    }

    /**
     * @param TokenInterface|UserInterface|string $user
     *
     * @return TokenInterface
     */
    protected function getUserToken($user)
    {
        if ($user instanceof TokenInterface) {
            return $user;
        } elseif ($user instanceof UserInterface) {
            return new FakeUserToken($user);
        } else {
            return new FakeUserToken(new User($user, ''));
        }
    }

    /**
     * @param string        $type
     * @param string|object $classOrObject
     * @param null|string   $field
     *
     * @return ObjectIdentity|FieldVote
     */
    protected function getObjectToSecure($type, $classOrObject, $field = null)
    {
        $objectIdentity = $this->getObjectIdentity($type, $classOrObject);

        if (null === $field) {
            return $objectIdentity;
        }

        return new FieldVote($objectIdentity, $field);
    }

    /**
     * @param string        $type
     * @param string|object $classOrObject
     *
     * @return ObjectIdentity
     * @throws \Exception
     */
    protected function getObjectIdentity($type, $classOrObject)
    {
        switch ($type) {
            case self::ACE_TYPE_CLASS:
                if (is_object($classOrObject)) {
                    $classOrObject = get_class($classOrObject);
                }

                return new ObjectIdentity($type, $classOrObject);
            case self::ACE_TYPE_OBJECT:
                return ObjectIdentity::fromDomainObject($classOrObject);
        }

        throw new AceTypeException($type);
    }
}
