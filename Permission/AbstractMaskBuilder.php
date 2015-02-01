<?php

namespace AlexDpy\AclBundle\Permission;

abstract class AbstractMaskBuilder implements MaskBuilderInterface
{
    /**
     * @var int
     */
    protected $mask;

    /**
     * Constructor.
     *
     * @param int $mask optional; defaults to 0
     */
    public function __construct($mask = 0)
    {
        $this->set($mask);
    }

    /**
     * {@inheritdoc}
     */
    public function set($mask)
    {
        if (!is_int($mask)) {
            throw new \InvalidArgumentException('$mask must be an integer.');
        }

        $this->mask = $mask;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function get()
    {
        return $this->mask;
    }

    /**
     * {@inheritdoc}
     */
    public function add($mask)
    {
        $this->mask |= $this->getMask($mask);

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function remove($mask)
    {
        $this->mask &= ~$this->getMask($mask);

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function reset()
    {
        $this->mask = 0;

        return $this;
    }
}
