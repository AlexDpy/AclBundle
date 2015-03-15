<?php

namespace AlexDpy\AclBundle\Manager;

use Doctrine\ORM\Query\SqlWalker;

class AclWalker extends SqlWalker
{
    /**
     * @param \Doctrine\ORM\Query\AST\WhereClause $whereClause
     * @return string
     */
    public function walkWhereClause($whereClause)
    {
        $sql =  parent::walkWhereClause($whereClause);
        $query = $this->getQuery();

        $subQuery = $query->getHint('acl_filter_sub_query');
        $oidReference = $query->getHint('acl_filter_oid_reference');

        $sql .= empty($sql) ? ' WHERE ' : ' AND ';

        $explode = explode('.', $oidReference, 2);
        $oidTableReference = $this->getQueryComponent($explode[0])['metadata']->table['name'];
        $oidAliasReference = $this->getSQLTableAlias($oidTableReference, $explode[0]);
        $newOidReference = $oidAliasReference . '.' . $explode[1];

        $subQuery = str_replace($oidReference, $newOidReference, $subQuery);

        $sql .= " $newOidReference IN(($subQuery))";

        return $sql;
    }
}
