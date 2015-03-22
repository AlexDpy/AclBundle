<?php

namespace AlexDpy\AclBundle\Manager;

use Doctrine\ORM\Query\SqlWalker;

class AclWalker extends SqlWalker
{
    /**
     * @param \Doctrine\ORM\Query\AST\FromClause $fromClause
     * @return string
     */
    public function walkFromClause($fromClause)
    {
        $sql = parent::walkFromClause($fromClause) . ' ';

        $aclTables = $this->getQuery()->getHint('acl_tables');
        $oidReference = $this->getQuery()->getHint('acl_filter_oid_reference');
        $oidClass = $this->getQuery()->getHint('acl_filter_oid_class');

        $explode = explode('.', $oidReference, 2);
        $oidTableReference = $this->getQueryComponent($explode[0])['metadata']->table['name'];
        $oidAliasReference = $this->getSQLTableAlias($oidTableReference, $explode[0]);
        $newOidReference = $oidAliasReference . '.' . $explode[1];

        $sql .= <<<SQL
LEFT JOIN {$aclTables['oid']} as acl_o ON {$newOidReference} = acl_o.object_identifier
LEFT JOIN {$aclTables['class']} as acl_c ON acl_o.id = acl_c.id
  AND acl_c.class_type = {$this->getConnection()->quote($oidClass)}
LEFT JOIN {$aclTables['entry']} as acl_e ON acl_o.class_id = acl_e.class_id
  AND (acl_o.id = acl_e.object_identity_id OR acl_e.object_identity_id IS NULL)
LEFT JOIN {$aclTables['sid']} as acl_s ON acl_e.security_identity_id = acl_s.id
SQL;

        return $sql;
    }

    /**
     * @param \Doctrine\ORM\Query\AST\WhereClause $whereClause
     * @return string
     */
    public function walkWhereClause($whereClause)
    {
        $sql =  parent::walkWhereClause($whereClause);

        $sidWhereClause = $this->getQuery()->getHint('acl_filter_sid_where_clause');
        $entriesWhereClause = $this->getQuery()->getHint('acl_filter_entries_where_clause');

        $sql .= empty($sql) ? ' WHERE ' : ' AND ';

        $sql .= $sidWhereClause . ' AND ' . $entriesWhereClause;

        return $sql;
    }
}
