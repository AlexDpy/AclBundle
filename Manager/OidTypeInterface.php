<?php

namespace AlexDpy\AclBundle\Manager;

use AlexDpy\AclBundle\Exception\OidTypeException;
use Symfony\Component\Security\Acl\Model\ObjectIdentityInterface;

interface OidTypeInterface
{
    const OID_TYPE_CLASS = 'class';
    const OID_TYPE_OBJECT = 'object';

    /**
     * @param string        $type
     * @param string|object $classOrObject
     *
     * @return ObjectIdentityInterface
     * @throws OidTypeException            When the $type is not supported
     */
    public function getObjectIdentity($type, $classOrObject);
}
