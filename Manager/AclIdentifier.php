<?php

namespace AlexDpy\AclBundle\Manager;

use AlexDpy\AclBundle\Exception\OidTypeException;
use Symfony\Component\Security\Acl\Domain\ObjectIdentity;
use Symfony\Component\Security\Acl\Domain\RoleSecurityIdentity;
use Symfony\Component\Security\Acl\Domain\UserSecurityIdentity;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Util\ClassUtils;

class AclIdentifier implements AclIdentifierInterface
{
    /**
     * @var SecurityContextInterface
     */
    protected $tokenStorage;

    /**
     * @param SecurityContextInterface $tokenStorage
     */
    public function __construct(SecurityContextInterface $tokenStorage)
    {
        $this->tokenStorage = $tokenStorage;
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
     * {@inheritdoc}
     */
    public function getUserSecurityIdentity(UserInterface $user = null)
    {
        return null === $user
            ? UserSecurityIdentity::fromToken($this->tokenStorage->getToken())
            : UserSecurityIdentity::fromAccount($user);
    }

    /**
     * {@inheritdoc}
     */
    public function getRoleSecurityIdentity($role)
    {
        return new RoleSecurityIdentity($role);
    }
}
