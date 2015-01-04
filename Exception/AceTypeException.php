<?php

namespace AlexDpy\AclBundle\Exception;

use AlexDpy\AclBundle\Manager\AclManager;

class AceTypeException extends \InvalidArgumentException
{
    /**
     * @param string $type
     */
    public function __construct($type)
    {
        parent::__construct(sprintf(
            '$type must be "' . AclManager::ACE_TYPE_CLASS . '" or "' . AclManager::ACE_TYPE_OBJECT . '", "%s" given',
            $type
        ));
    }

}
