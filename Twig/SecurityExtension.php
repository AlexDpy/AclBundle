<?php

namespace AlexDpy\AclBundle\Twig;

use AlexDpy\AclBundle\Manager\AclManager;

class SecurityExtension extends \Twig_Extension
{
    /**
     * @var AclManager
     */
    protected $aclManager;

    /**
     * @param AclManager $aclManager
     */
    public function __construct(AclManager $aclManager)
    {
        $this->aclManager = $aclManager;
    }

    /**
     * {@inheritdoc}
     */
    public function getFunctions()
    {
        return [
            new \Twig_SimpleFunction('is_granted', [$this->aclManager, 'isGranted']),
            new \Twig_SimpleFunction('isGranted', [$this->aclManager, 'isGranted']),
            new \Twig_SimpleFunction('isGrantedAgainstClass', [$this->aclManager, 'isGrantedAgainstClass']),
            new \Twig_SimpleFunction('isGrantedAgainstObject', [$this->aclManager, 'isGrantedAgainstObject']),
            new \Twig_SimpleFunction('roleIsGranted', [$this->aclManager, 'roleIsGranted']),
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
 