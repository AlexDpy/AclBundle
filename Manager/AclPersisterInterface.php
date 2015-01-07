<?php

namespace AlexDpy\AclBundle\Manager;

use Symfony\Component\Security\Core\Role\Role;
use Symfony\Component\Security\Core\User\UserInterface;

interface AclPersisterInterface
{
    /**
     * @param string|string[] $permissions
     * @param string|object   $class
     * @param string|Role     $role
     * @param null|string     $field
     */
    public function grantRoleOnClass($permissions, $class, $role, $field = null);

    /**
     * @param string|string[] $permissions
     * @param object          $object
     * @param string|Role     $role
     * @param null|string     $field
     */
    public function grantRoleOnObject($permissions, $object, $role, $field = null);

    /**
     * @param string|string[]    $permissions
     * @param string|object      $class
     * @param null|UserInterface $user
     * @param null|string        $field
     */
    public function grantUserOnClass($permissions, $class, UserInterface $user = null, $field = null);

    /**
     * @param string|string[]    $permissions
     * @param object             $object
     * @param null|UserInterface $user
     * @param null|string        $field
     */
    public function grantUserOnObject($permissions, $object, UserInterface $user = null, $field = null);

    /**
     * @param string|string[] $permissions
     * @param string|object   $class
     * @param string|Role     $role
     * @param null|string     $field
     */
    public function revokeRoleOnClass($permissions, $class, $role, $field = null);

    /**
     * @param string|string[] $permissions
     * @param object          $object
     * @param string|Role     $role
     * @param null|string     $field
     */
    public function revokeRoleOnObject($permissions, $object, $role, $field = null);

    /**
     * @param string|string[]    $permissions
     * @param string|object      $class
     * @param null|UserInterface $user
     * @param null|string        $field
     */
    public function revokeUserOnClass($permissions, $class, UserInterface $user = null, $field = null);

    /**
     * @param string|string[]    $permissions
     * @param object             $object
     * @param null|UserInterface $user
     * @param null|string        $field
     */
    public function revokeUserOnObject($permissions, $object, UserInterface $user = null, $field = null);

    /**
     * @param string|object $class
     */
    public function deleteAclForClass($class);

    /**
     * @param object $object
     */
    public function deleteAclForObject($object);
}
