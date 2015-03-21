<?php

namespace AlexDpy\AclBundle\DependencyInjection\CompilerPass;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

class SecurityContextCompilerPass implements CompilerPassInterface
{
    /**
     * {@inheritdoc}
     */
    public function process(ContainerBuilder $container)
    {
        if (!$container->has('security.token_storage')) {
            $container->getDefinition('alex_dpy_acl.acl_identifier')
                ->replaceArgument(0, new Reference('security.context'));

            $container->getDefinition('alex_dpy_acl.acl_filter')
                ->replaceArgument(2, new Reference('security.context'));
        }

        if (!$container->has('security.authorization_checker')) {
            $container->getDefinition('alex_dpy_acl.acl_checker')
                ->replaceArgument(1, new Reference('security.context'));
        }
    }
}
