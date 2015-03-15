<?php

namespace AlexDpy\AclBundle\DependencyInjection\CompilerPass;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

class TwigCompilerPass implements CompilerPassInterface
{
    /**
     * {@inheritdoc}
     */
    public function process(ContainerBuilder $container)
    {
        if (!$container->has('twig.extension.security')) {
            return;
        }

        $aclExtensionDef = new Definition('AlexDpy\AclBundle\Twig\AclExtension', [
            new Reference('alex_dpy_acl.acl_checker')
        ]);

        $aclExtensionDef->addTag('twig.extension');

        $container->setDefinition('alex_dpy_acl.acl_extension', $aclExtensionDef);
    }
}
