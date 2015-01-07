<?php

namespace AlexDpy\AclBundle\Manager;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Role\RoleInterface;
use Symfony\Component\Security\Core\User\UserInterface;

interface AclCheckerInterface
{
    /**
     * @param mixed              $attributes
     * @param null|string|object $classOrObject
     * @param null|string        $field
     *
     * @return bool
     */
    public function isGranted($attributes, $classOrObject = null, $field = null);

    /**
     * @param mixed         $attributes
     * @param string|object $class
     * @param null|string   $field
     *
     * @return bool
     */
    public function isGrantedOnClass($attributes, $class, $field = null);

    /**
     * @param mixed        $attributes
     * @param object       $object
     * @param null|string  $field
     *
     * @return bool
     */
    public function isGrantedOnObject($attributes, $object, $field = null);

    /**
     * @param string|array|RoleInterface|TokenInterface $role
     * @param mixed                                     $attributes
     * @param null|string|object                        $classOrObject
     * @param null|string                               $field
     *
     * @return bool
     */
    public function roleIsGranted($role, $attributes, $classOrObject = null, $field = null);

    /**
     * @param string|array|RoleInterface|TokenInterface $role
     * @param mixed                                     $attributes
     * @param string|object                             $class
     * @param null|string                               $field
     *
     * @return bool
     */
    public function roleIsGrantedOnClass($role, $attributes, $class, $field = null);

    /**
     * @param string|array|RoleInterface|TokenInterface $role
     * @param mixed                                     $attributes
     * @param object                                    $object
     * @param null|string                               $field
     *
     * @return bool
     */
    public function roleIsGrantedOnObject($role, $attributes, $object, $field = null);

    /**
     * @param TokenInterface|UserInterface|string $user
     * @param mixed                               $attributes
     * @param null|string|object                  $classOrObject
     * @param null|string                         $field
     *
     * @return bool
     */
    public function userIsGranted($user, $attributes, $classOrObject = null, $field = null);

    /**
     * @param TokenInterface|UserInterface|string $user
     * @param mixed                               $attributes
     * @param string|object                       $class
     * @param null|string                         $field
     *
     * @return bool
     */
    public function userIsGrantedOnClass($user, $attributes, $class, $field = null);

    /**
     * @param TokenInterface|UserInterface|string $user
     * @param mixed                               $attributes
     * @param object                              $object
     * @param null|string                         $field
     *
     * @return bool
     */
    public function userIsGrantedOnObject($user, $attributes, $object, $field = null);
}
