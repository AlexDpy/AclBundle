<?php

namespace AlexDpy\AclBundle\Twig;

use AlexDpy\AclBundle\Manager\AclCheckerInterface;

class SecurityExtension extends \Twig_Extension
{
    /**
     * @var AclCheckerInterface
     */
    protected $aclChecker;

    /**
     * @param AclCheckerInterface $aclChecker
     */
    public function __construct(AclCheckerInterface $aclChecker)
    {
        $this->aclChecker = $aclChecker;
    }

    /**
     * {@inheritdoc}
     */
    public function getFunctions()
    {
        return [
            new \Twig_SimpleFunction('is_granted', [$this->aclChecker, 'isGranted']),
            new \Twig_SimpleFunction('isGranted', [$this->aclChecker, 'isGranted']),
            new \Twig_SimpleFunction('isGrantedOnClass', [$this->aclChecker, 'isGrantedOnClass']),
            new \Twig_SimpleFunction('isGrantedOnObject', [$this->aclChecker, 'isGrantedOnObject']),
            new \Twig_SimpleFunction('roleIsGranted', [$this->aclChecker, 'roleIsGranted']),
        ];
    }
    /**
     * {@inheritdoc}
     */
    public function getName()
    {
        return 'alex_dpy_acl_security';
    }
}
