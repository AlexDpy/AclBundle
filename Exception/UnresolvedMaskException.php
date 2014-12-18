<?php

namespace AlexDpy\AclBundle\Exception;

class UnresolvedMaskException extends \Exception
{
    /**
     * @param string $permission
     *
     * @return UnresolvedMaskException
     */
    public static function nonExistentPermission($permission)
    {
        return new self(sprintf('Permission "%s" does not exist in this permissionMap', $permission));
    }

    /**
     * @param string      $permission
     * @param null|string $object
     *
     * @return UnresolvedMaskException
     */
    public static function nonSupportedPermission($permission, $object = null)
    {
        if (null === $object) {
            return new self(sprintf('Permission "%s" is not supported in this permissionMap', $permission));
        } else {
            return new self(sprintf('Permission/object (%s/%s) combination is not supported in the permissionMap',
                $permission,
                $object
            ));
        }
    }
}
