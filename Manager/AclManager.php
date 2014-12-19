<?php

namespace AlexDpy\AclBundle\Manager;

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
            return $this->isGrantedAgainstClass($attributes, $classOrObject, $field);
        } elseif (is_object($classOrObject)) {
            return $this->isGrantedAgainstObject($attributes, $classOrObject, $field);
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
    public function isGrantedAgainstClass($attributes, $class, $field = null)
    {
        if (is_object($class)) {
            $class = get_class($class);
        }

        $object = null === $field
            ? new ObjectIdentity(self::ACE_TYPE_CLASS, $class)
            : new FieldVote(new ObjectIdentity(self::ACE_TYPE_CLASS, $class), $field);

        return $this->authorizationChecker->isGranted($attributes, $object);
    }

    /**
     * @param string|array $attributes
     * @param object       $object
     * @param null|string  $field
     *
     * @return bool
     */
    public function isGrantedAgainstObject($attributes, $object, $field = null)
    {
        if (null !== $field) {
            $object = new FieldVote(ObjectIdentity::fromDomainObject($object), $field);
        }

        return $this->authorizationChecker->isGranted($attributes, $object);
    }

    /**
     * @param string|RoleInterface $role
     * @param string|array         $attributes
     * @param null|string|object   $classOrObject
     * @param null|string          $field
     *
     * @return bool
     */
    public function roleIsGranted($role, $attributes, $classOrObject = null, $field = null)
    {
        $fakeRoleToken = new FakeRoleToken((array) $role);

        if (null === $classOrObject) {
            return $this->accessDecisionManager->decide($fakeRoleToken, (array) $attributes, $classOrObject);
        } elseif (is_string($classOrObject)) {
            return $this->roleIsGrantedAgainstClass($fakeRoleToken, (array) $attributes, $classOrObject, $field);
        } elseif (is_object($classOrObject)) {
            return $this->roleIsGrantedAgainstObject($fakeRoleToken, (array) $attributes, $classOrObject, $field);
        }

        return false;
    }

    /**
     * @param string|RoleInterface|TokenInterface $role
     * @param string|array                        $attributes
     * @param string|object                       $class
     * @param null|string                         $field
     *
     * @return bool
     */
    public function roleIsGrantedAgainstClass($role, $attributes, $class, $field = null)
    {
        $fakeRoleToken = $role instanceof TokenInterface ? $role :  new FakeRoleToken((array) $role);

        if (is_object($class)) {
            $class = get_class($class);
        }

        $object = null === $field
            ? new ObjectIdentity(self::ACE_TYPE_CLASS, $class)
            : new FieldVote(new ObjectIdentity(self::ACE_TYPE_CLASS, $class), $field);

        return $this->accessDecisionManager->decide($fakeRoleToken, (array) $attributes, $object);
    }

    /**
     * @param string|RoleInterface|TokenInterface $role
     * @param string|array                        $attributes
     * @param object                              $object
     * @param null|string                         $field
     *
     * @return bool
     */
    public function roleIsGrantedAgainstObject($role, $attributes, $object, $field = null)
    {
        $fakeRoleToken = $role instanceof TokenInterface ? $role :  new FakeRoleToken((array) $role);

        if (null !== $field) {
            $object = new FieldVote(ObjectIdentity::fromDomainObject($object), $field);
        }

        return $this->accessDecisionManager->decide($fakeRoleToken, (array) $attributes, $object);
    }

    /**
     * @param TokenInterface|UserInterface|string $user
     * @param string|array                        $attributes
     * @param null|string|object                  $classOrObject
     * @param null|string                         $field
     *
     * @return bool
     * @throws \Exception
     */
    public function userIsGranted($user, $attributes, $classOrObject = null, $field = null)
    {
        //@TODO
        if ($user instanceof TokenInterface) {
            $token = $user;
        } elseif ($user instanceof UserInterface) {
            $token = new FakeUserToken($user);
        } elseif (is_string($user)) {
            $token = new FakeUserToken(new User($user, ''));//@TODO comment récupérer la bonne classe User ?
        } else {
            throw new \Exception; //@TODO
        }

        if (null === $classOrObject) {
            return $this->accessDecisionManager->decide($token, (array) $attributes, $classOrObject);
        } elseif (is_string($classOrObject)) {
            return $this->userIsGrantedAgainstClass($token, (array) $attributes, $classOrObject, $field);
        } elseif (is_object($classOrObject)) {
            return $this->userIsGrantedAgainstObject($token, (array) $attributes, $classOrObject, $field);
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
    public function userIsGrantedAgainstClass($user, $attributes, $class, $field = null)
    {
        //@TODO
        if ($user instanceof TokenInterface) {
            $token = $user;
        } elseif ($user instanceof UserInterface) {
            $token = new FakeUserToken($user);
        } elseif (is_string($user)) {
            $token = new FakeUserToken(new User($user, ''));
        } else {
            throw new \Exception; //@TODO
        }

        if (is_object($class)) {
            $class = get_class($class);
        }

        $object = null === $field
            ? new ObjectIdentity(self::ACE_TYPE_CLASS, $class)
            : new FieldVote(new ObjectIdentity(self::ACE_TYPE_CLASS, $class), $field);

        return $this->accessDecisionManager->decide($token, (array) $attributes, $object);
    }

    public function userIsGrantedAgainstObject($user, $attributes, $object, $field = null)
    {
        //@TODO
        if ($user instanceof TokenInterface) {
            $token = $user;
        } elseif ($user instanceof UserInterface) {
            $token = new FakeUserToken($user);
        } elseif (is_string($user)) {
            $token = new FakeUserToken(new User($user, ''));
        } else {
            throw new \Exception; //@TODO
        }

        if (null !== $field) {
            $object = new FieldVote(ObjectIdentity::fromDomainObject($object), $field);
        }

        return $this->accessDecisionManager->decide($token, (array) $attributes, $object);
    }

    /**
     * @param string|array  $permissions
     * @param string|object $class
     * @param string|Role   $role
     * @param null|string   $field
     */
    public function grantRoleAgainstClass($permissions, $class, $role, $field = null)
    {
        if (is_object($class)) {
            $class = get_class($class);
        }

        $objectIdentity = new ObjectIdentity(self::ACE_TYPE_CLASS, $class);
        $securityIdentity = $this->getRoleSecurityIdentity($role);

        $acl = $this->findOrCreateAcl($objectIdentity);

        $this->insertAces($acl, $securityIdentity, $permissions, self::ACE_TYPE_CLASS, $field);
    }

    /**
     * @param string|array $permissions
     * @param object       $object
     * @param string|Role  $role
     * @param null|string  $field
     */
    public function grantRoleAgainstObject($permissions, $object, $role, $field = null)
    {
        $objectIdentity = ObjectIdentity::fromDomainObject($object);
        $securityIdentity = $this->getRoleSecurityIdentity($role);

        $acl = $this->findOrCreateAcl($objectIdentity);

        $this->insertAces($acl, $securityIdentity, $permissions, self::ACE_TYPE_OBJECT, $field);
    }

    /**
     * @param string|array       $permissions
     * @param string|object      $class
     * @param null|UserInterface $user
     * @param null|string        $field
     */
    public function grantUserAgainstClass($permissions, $class, UserInterface $user = null, $field = null)
    {
        if (is_object($class)) {
            $class = get_class($class);
        }

        $objectIdentity = new ObjectIdentity(self::ACE_TYPE_CLASS, $class);
        $securityIdentity = $this->getUserSecurityIdentity($user);

        $acl = $this->findOrCreateAcl($objectIdentity);

        $this->insertAces($acl, $securityIdentity, $permissions, self::ACE_TYPE_CLASS, $field);
    }

    /**
     * @param string|array       $permissions
     * @param object             $object
     * @param null|UserInterface $user
     * @param null|string        $field
     */
    public function grantUserAgainstObject($permissions, $object, UserInterface $user = null, $field = null)
    {
        $objectIdentity = ObjectIdentity::fromDomainObject($object);
        $securityIdentity = $this->getUserSecurityIdentity($user);

        $acl = $this->findOrCreateAcl($objectIdentity);

        $this->insertAces($acl, $securityIdentity, $permissions, self::ACE_TYPE_OBJECT, $field);
    }

    /**
     * @param string|array  $permissions
     * @param string|object $class
     * @param string|Role   $role
     * @param null|string   $field
     */
    public function revokeRoleAgainstClass($permissions, $class, $role, $field = null)
    {
        if (is_object($class)) {
            $class = get_class($class);
        }

        $objectIdentity = new ObjectIdentity(self::ACE_TYPE_CLASS, $class);
        $securityIdentity = $this->getRoleSecurityIdentity($role);

        if (null !== $acl = $this->findAcl($objectIdentity)) {
            $this->deleteAces($acl, $securityIdentity, $permissions, self::ACE_TYPE_CLASS, $field);
        }
    }

    /**
     * @param string|array $permissions
     * @param object       $object
     * @param string|Role  $role
     * @param null|string  $field
     */
    public function revokeRoleAgainstObject($permissions, $object, $role, $field = null)
    {
        $objectIdentity = ObjectIdentity::fromDomainObject($object);
        $securityIdentity = $this->getRoleSecurityIdentity($role);

        if (null !== $acl = $this->findAcl($objectIdentity)) {
            $this->deleteAces($acl, $securityIdentity, $permissions, self::ACE_TYPE_OBJECT, $field);
        }
    }

    /**
     * @param string|array       $permissions
     * @param string|object      $class
     * @param null|UserInterface $user
     * @param null|string        $field
     */
    public function revokeUserAgainstClass($permissions, $class, UserInterface $user = null, $field = null)
    {
        if (is_object($class)) {
            $class = get_class($class);
        }

        $objectIdentity = new ObjectIdentity(self::ACE_TYPE_CLASS, $class);
        $securityIdentity = $this->getUserSecurityIdentity($user);

        if (null !== $acl = $this->findAcl($objectIdentity)) {
            $this->deleteAces($acl, $securityIdentity, $permissions, self::ACE_TYPE_CLASS, $field);
        }
    }

    /**
     * @param string|array       $permissions
     * @param object             $object
     * @param null|UserInterface $user
     * @param null|string        $field
     */
    public function revokeUserAgainstObject($permissions, $object, UserInterface $user = null, $field = null)
    {
        $objectIdentity = ObjectIdentity::fromDomainObject($object);
        $securityIdentity = $this->getUserSecurityIdentity($user);

        if (null !== $acl = $this->findAcl($objectIdentity)) {
            $this->deleteAces($acl, $securityIdentity, $permissions, self::ACE_TYPE_OBJECT, $field);
        }
    }

    /**
     * @param MutableAclInterface       $acl
     * @param SecurityIdentityInterface $securityIdentity
     * @param string|array              $permissions
     * @param string                    $type             class|object
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
     * @param string                    $type             class|object
     * @param null|string               $field
     */
    protected function deleteAces(MutableAclInterface $acl, SecurityIdentityInterface $securityIdentity, $permissions, $type, $field = null)
    {
        $type = ucfirst($type);
        $getMethod = null === $field ? 'get' . $type . 'Aces' : 'get' . $type . 'FieldAces';
        $deleteMethod = null === $field ? 'delete' . $type . 'Ace' : 'delete' . $type . 'FieldAce';

        $permissions = (array) $permissions;
        foreach ($permissions as $permission) {
            $mask = max($this->resolveMasks($permission));

            foreach ($acl->{$getMethod}($field) as $index => $ace) {
                if ($mask <= $ace->getMask() && $securityIdentity->equals($ace->getSecurityIdentity())) {
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
     * @param string                    $type             class|object
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
}
