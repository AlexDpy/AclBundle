<?php

namespace AlexDpy\AclBundle\Manager;

use AlexDpy\AclBundle\Token\FakeRoleToken;
use AlexDpy\AclBundle\Token\FakeUserToken;
use Symfony\Component\Security\Acl\Domain\ObjectIdentity;
use Symfony\Component\Security\Acl\Voter\FieldVote;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManagerInterface;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Core\Role\RoleInterface;
use Symfony\Component\Security\Core\User\User;
use Symfony\Component\Security\Core\User\UserInterface;

class AclChecker implements AclCheckerInterface
{
    /**
     * @var AclManagerInterface
     */
    protected $aclManager;
    
    /**
     * @var AuthorizationCheckerInterface $authorizationChecker
     */
    protected $authorizationChecker;

    /**
     * @var AccessDecisionManagerInterface $accessDecisionManager
     */
    protected $accessDecisionManager;

    /**
     * @param AuthorizationCheckerInterface  $authorizationChecker
     * @param AccessDecisionManagerInterface $accessDecisionManager
     */
    public function __construct(
        AclManagerInterface $aclManager,
        AuthorizationCheckerInterface $authorizationChecker,
        AccessDecisionManagerInterface $accessDecisionManager
    ) {
        $this->aclManager = $aclManager;
        $this->authorizationChecker = $authorizationChecker;
        $this->accessDecisionManager = $accessDecisionManager;
    }

    /**
     * {@inheritdoc}
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
     * {@inheritdoc}
     */
    public function isGrantedOnClass($attributes, $class, $field = null)
    {
        return $this->authorizationChecker->isGranted(
            $attributes,
            $this->getObjectToSecure(AclManagerInterface::OID_TYPE_CLASS, $class, $field)
        );
    }

    /**
     * {@inheritdoc}
     */
    public function isGrantedOnObject($attributes, $object, $field = null)
    {
        return $this->authorizationChecker->isGranted(
            $attributes,
            $this->getObjectToSecure(AclManagerInterface::OID_TYPE_OBJECT, $object, $field)
        );
    }

    /**
     * {@inheritdoc}
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
     * {@inheritdoc}
     */
    public function roleIsGrantedOnClass($role, $attributes, $class, $field = null)
    {
        return $this->accessDecisionManager->decide(
            $this->getRoleToken($role),
            (array) $attributes,
            $this->getObjectToSecure(AclManagerInterface::OID_TYPE_CLASS, $class, $field)
        );
    }

    /**
     * {@inheritdoc}
     */
    public function roleIsGrantedOnObject($role, $attributes, $object, $field = null)
    {
        return $this->accessDecisionManager->decide(
            $this->getRoleToken($role),
            (array) $attributes,
            $this->getObjectToSecure(AclManagerInterface::OID_TYPE_OBJECT, $object, $field)
        );
    }

    /**
     * {@inheritdoc}
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
     * {@inheritdoc}
     */
    public function userIsGrantedOnClass($user, $attributes, $class, $field = null)
    {
        return $this->accessDecisionManager->decide(
            $this->getUserToken($user),
            (array) $attributes,
            $this->getObjectToSecure(AclManagerInterface::OID_TYPE_CLASS, $class, $field)
        );
    }

    /**
     * {@inheritdoc}
     */
    public function userIsGrantedOnObject($user, $attributes, $object, $field = null)
    {
        return $this->accessDecisionManager->decide(
            $this->getUserToken($user),
            (array) $attributes,
            $this->getObjectToSecure(AclManagerInterface::OID_TYPE_OBJECT, $object, $field)
        );
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
        $objectIdentity = $this->aclManager->getObjectIdentity($type, $classOrObject);

        if (null === $field) {
            return $objectIdentity;
        }

        return new FieldVote($objectIdentity, $field);
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
}
 