<?php

namespace AlexDpy\AclBundle\DependencyInjection\CompilerPass;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

class OrmCompilerPass implements CompilerPassInterface
{
    /**
     * You can modify the container here before it is dumped to PHP code.
     *
     * @param ContainerBuilder $container
     *
     * @api
     */
    public function process(ContainerBuilder $container)
    {
        if (!$container->has('doctrine')) {
            return;
        }

        $aclFilterDef = $container->getDefinition('alex_dpy_acl.acl_filter');
        $aclFilterDef->addMethodCall('setAclWalker', ['AlexDpy\AclBundle\Manager\AclWalker']);
    }
}
