<?php

namespace AlexDpy\AclBundle\DataCollector\Collector;

use AlexDpy\AclBundle\Manager\AclIdentifierInterface;
use AlexDpy\AclBundle\Manager\AclManagerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Stopwatch\Stopwatch;

class AclManagerCollector implements AclManagerInterface
{
    /**
     * @var AclManagerInterface
     */
    private $aclManager;

    /**
     * @var Stopwatch
     */
    private $stopwatch;

    /**
     * @var array
     */
    private $managements;

    /**
     * @var AclIdentifierInterface
     */
    private $aclIdentifier;

    /**
     * @param AclManagerInterface $aclManager
     * @param Stopwatch           $stopwatch
     */
    public function __construct(AclManagerInterface $aclManager, Stopwatch $stopwatch)
    {
        $aclIdentifierProperty = new \ReflectionProperty('AlexDpy\AclBundle\Manager\AclManager', 'aclIdentifier');
        $aclIdentifierProperty->setAccessible(true);
        $this->aclIdentifier = $aclIdentifierProperty->getValue($aclManager);

        $this->aclManager = $aclManager;
        $this->stopwatch = $stopwatch;
        $this->managements = [];
    }

    /**
     * @param string $function
     * @param array  $arguments
     *
     * @return mixed
     */
    private function collectManagement($function, $arguments)
    {
        $this->stopwatch->start('acl.managements');

        $result = call_user_func_array([$this->aclManager, $function], $arguments);

        $periods = $this->stopwatch->stop('acl.managements')->getPeriods();

        $backtrace = debug_backtrace(0, 2)[1];

        $oidType = 'Class' === substr($function, -5)
            ? AclIdentifierInterface::OID_TYPE_CLASS
            : AclIdentifierInterface::OID_TYPE_OBJECT;

        if ('delete' === substr($function, 0, 6)) {
            $permissions = null;
            $oid = $this->aclIdentifier->getObjectIdentity($oidType, $backtrace['args'][0]);
            $sid = null;
            $field = null;
        } else {
            $permissions = $backtrace['args'][0];
            $oid = $this->aclIdentifier->getObjectIdentity($oidType, $backtrace['args'][1]);
            $sid = false !== strpos($function, 'Role')
                ? $this->aclIdentifier->getRoleSecurityIdentity($backtrace['args'][2])
                : $this->aclIdentifier->getUserSecurityIdentity(
                    isset($backtrace['args'][2]) ? $backtrace['args'][2] : null
                );
            $field = isset($backtrace['args'][3]) ? $backtrace['args'][3] : null;
        }

        $this->managements[] = [
            'method' => $function,
            'permissions' => (array) $permissions,
            'oid' => $oid,
            'sid' => $sid,
            'field' => $field,
            'time' => end($periods)->getDuration()
        ];
        
        return $result;
    }

    /**
     * {@inheritdoc}
     */
    public function grantRoleOnClass($permissions, $class, $role, $field = null)
    {
        return $this->collectManagement(__FUNCTION__, func_get_args());
    }

    /**
     * {@inheritdoc}
     */
    public function grantRoleOnObject($permissions, $object, $role, $field = null)
    {
        return $this->collectManagement(__FUNCTION__, func_get_args());
    }

    /**
     * {@inheritdoc}
     */
    public function grantUserOnClass($permissions, $class, UserInterface $user = null, $field = null)
    {
        return $this->collectManagement(__FUNCTION__, func_get_args());
    }

    /**
     * {@inheritdoc}
     */
    public function grantUserOnObject($permissions, $object, UserInterface $user = null, $field = null)
    {
        return $this->collectManagement(__FUNCTION__, func_get_args());
    }

    /**
     * {@inheritdoc}
     */
    public function revokeRoleOnClass($permissions, $class, $role, $field = null)
    {
        return $this->collectManagement(__FUNCTION__, func_get_args());
    }

    /**
     * {@inheritdoc}
     */
    public function revokeRoleOnObject($permissions, $object, $role, $field = null)
    {
        return $this->collectManagement(__FUNCTION__, func_get_args());
    }

    /**
     * {@inheritdoc}
     */
    public function revokeUserOnClass($permissions, $class, UserInterface $user = null, $field = null)
    {
        return $this->collectManagement(__FUNCTION__, func_get_args());
    }

    /**
     * {@inheritdoc}
     */
    public function revokeUserOnObject($permissions, $object, UserInterface $user = null, $field = null)
    {
        return $this->collectManagement(__FUNCTION__, func_get_args());
    }

    /**
     * {@inheritdoc}
     */
    public function deleteAclForClass($class)
    {
        return $this->collectManagement(__FUNCTION__, func_get_args());
    }

    /**
     * {@inheritdoc}
     */
    public function deleteAclForObject($object)
    {
        return $this->collectManagement(__FUNCTION__, func_get_args());
    }

    /**
     * @param $method
     * @param $arguments
     * @return mixed
     */
    public function __call($method, $arguments)
    {
        return call_user_func_array([$this->aclManager, $method], $arguments);
    }
}
