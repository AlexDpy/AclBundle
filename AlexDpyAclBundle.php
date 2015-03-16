<?php

namespace AlexDpy\AclBundle;

use AlexDpy\AclBundle\DependencyInjection\CompilerPass\OrmCompilerPass;
use AlexDpy\AclBundle\DependencyInjection\CompilerPass\SecurityContextCompilerPass;
use AlexDpy\AclBundle\DependencyInjection\CompilerPass\TwigCompilerPass;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

class AlexDpyAclBundle extends Bundle
{
    public function build(ContainerBuilder $container)
    {
        $container->addCompilerPass(new OrmCompilerPass());
        $container->addCompilerPass(new TwigCompilerPass());
        $container->addCompilerPass(new SecurityContextCompilerPass());
    }
}
