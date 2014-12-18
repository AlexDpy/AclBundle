<?php

namespace AlexDpy\AclBundle\Exception;

class UnresolvedMaskException extends \Exception
{
    /**
     * @param $constantPath
     * @param $resolvedMask
     *
     * @return UnresolvedMaskException
     */
    public static function wrongType($constantPath, $resolvedMask)
    {
        return new self(sprintf(
            'The resolved mask must be an integer, but %s is a(n) %s.',
            $constantPath,
            gettype($resolvedMask)
        ));
    }
}
