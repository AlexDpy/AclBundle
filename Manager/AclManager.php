<?php

namespace AlexDpy\AclBundle\Manager;

use AlexDpy\AclBundle\Exception\OidTypeException;
use Symfony\Component\Security\Acl\Domain\ObjectIdentity;
use Symfony\Component\Security\Core\Util\ClassUtils;

class AclManager implements AclManagerInterface
{
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
}
