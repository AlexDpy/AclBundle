<?php

namespace AlexDpy\AclBundle\Manager;

use AlexDpy\AclBundle\Exception\UnresolvedMaskException;
use AlexDpy\AclBundle\Token\FakeRoleToken;
use Symfony\Component\Security\Acl\Domain\ObjectIdentity;
use Symfony\Component\Security\Acl\Domain\RoleSecurityIdentity;
use Symfony\Component\Security\Acl\Domain\UserSecurityIdentity;
use Symfony\Component\Security\Acl\Exception\AclNotFoundException;
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
            $object = new FieldVote(ObjectIdentity::fromDomainObject($object), $field); //@TODO need ObjectIdentity::fromDomainObject($object) ??? à tester
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

        return $this->accessDecisionManager->decide($fakeRoleToken, $attributes, $object);
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
            $object = new FieldVote(ObjectIdentity::fromDomainObject($object), $field); //@TODO need ObjectIdentity::fromDomainObject($object) ??? à tester
        }

        return $this->accessDecisionManager->decide($fakeRoleToken, $attributes, $object);
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

    public function revokeRoleAgainstObject()
    {
        //@TODO
    }

    /**
     * @param MutableAclInterface       $acl
     * @param SecurityIdentityInterface $securityIdentity
     * @param string|array              $permissions
     * @param string                    $type             class|object
     * @param null|string               $field
     *
     * @throws \InvalidArgumentException
     */
    protected function insertAces(MutableAclInterface $acl, SecurityIdentityInterface $securityIdentity, $permissions, $type, $field = null)
    {
        $permissions = (array) $permissions;
        foreach ($permissions as $permission) {
            $mask = $this->getSmallestMask($permission);

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
     *
     * @throws \InvalidArgumentException
     */
    protected function deleteAces(MutableAclInterface $acl, SecurityIdentityInterface $securityIdentity, $permissions, $type, $field = null)
    {
        $permissions = (array) $permissions;
        foreach ($permissions as $permission) {
            $mask = $this->getBiggestMask($permission);

            $getMethod = null === $field ? 'get' . ucfirst($type) . 'Aces' : 'get' . ucfirst($type) . 'FieldAces';
            $deleteMethod = null === $field ? 'delete' . ucfirst($type) . 'Ace' : 'delete' . ucfirst($type) . 'FieldAce';

            foreach ($acl->{$getMethod}($field) as $index => $ace) {
                if ($mask === $ace->getMask() && $securityIdentity->equals($ace->getSecurityIdentity())) {
                    $acl->{$deleteMethod}($index, $field);
                }
            }
        }

        $this->aclProvider->updateAcl($acl);
    }

    /**
     * @param MutableAclInterface       $acl
     * @param SecurityIdentityInterface $securityIdentity
     * @param int                       $mask
     * @param string                    $type             class|object
     * @param null|string               $field
     *
     * @return bool
     * @throws \InvalidArgumentException
     */
    protected function hasAce(MutableAclInterface $acl, SecurityIdentityInterface $securityIdentity, $mask, $type, $field = null)
    {
        $method = null === $field ? 'get' . ucfirst($type) . 'Aces' : 'get' . ucfirst($type) . 'FieldAces';

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
     * @return \Symfony\Component\Security\Acl\Model\AclInterface|\Symfony\Component\Security\Acl\Model\MutableAclInterface
     */
    protected function findOrCreateAcl(ObjectIdentityInterface $objectIdentity)
    {
        try {
            $acl = $this->aclProvider->findAcl($objectIdentity);
        } catch (AclNotFoundException $e) {
            $acl = $this->aclProvider->createAcl($objectIdentity);
        }

        return $acl;
    }

    /**
     * @param ObjectIdentityInterface $objectIdentity
     *
     * @return null|\Symfony\Component\Security\Acl\Model\AclInterface
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
     * @param $permission
     *
     * @return mixed
     * @throws \Exception
     */
    protected function getSmallestMask($permission)
    {
        if (
            !$this->permissionMap->contains(strtoupper($permission)) ||
            null !== $masks = $this->permissionMap->getMasks($permission, null)
        ) {
            throw new \Exception;
        }

        return min($masks);
    }

    /**
     * @param string $permission
     *
     * @return int
     * @throws \Exception
     */
    protected function getBiggestMask($permission)
    {
        if (
            !$this->permissionMap->contains(strtoupper($permission)) ||
            null !== $masks = $this->permissionMap->getMasks($permission, null)
        ) {
            throw new \Exception;
        }

        return max($masks);
//
//        $mask = constant('AppBundle\Security\PermissionMap::MASK_' . strtoupper($permission));
//
//        if (!is_int($mask)) {
//            throw UnresolvedMaskException::wrongType(
//                'AppBundle\Security\PermissionMap::MASK_' . strtoupper($permission),
//                $mask
//            );
//        }
//
//        return $mask;
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
