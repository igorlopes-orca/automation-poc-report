# A) CRITICAL E ALTO ALERTAS IDENTIFICADOS EM X REPOSITORIOS: AMOUNT OF REPOSITORIES NEED TO BE COUNTED AS PART OF THE WORKFLOW
curl -X POST 'https://api.orcasecurity.io/api/serving-layer/query'         -H 'authority: api.orcasecurity.io'         -H 'accept: application/json, text/plain, */*'         -H 'accept-language: en-US,en;q=0.9'         -H 'authorization: TOKEN {{ORCA_API_TOKEN}}'         -H 'content-type: application/json'         --data-raw '{
  "query": {
    "models": [
      "Alert"
    ],
    "type": "object_set",
    "with": {
      "operator": "and",
      "type": "operation",
      "values": [
        {
          "key": "Labels",
          "values": [
            {
              "key": "Labels",
              "values": [
                "source:shiftleft"
              ],
              "type": "str",
              "operator": "in"
            }
          ],
          "type": "list",
          "operator": "any_match"
        },
        {
          "key": "Status",
          "values": [
            "open",
            "in_progress"
          ],
          "type": "str",
          "operator": "in"
        },
        {
          "key": "RiskLevel",
          "values": [
            "critical",
            "high"
          ],
          "type": "str",
          "operator": "in"
        }
      ]
    }
  },
  "limit": 100,
  "start_at_index": 0,
  "order_by[]": [
    "-OrcaScore"
  ],
  "select": [
    "AlertId",
    "AlertType",
    "Status",
    "OrcaScore",
    "RiskLevel",
    "RuleSource",
    "RuleType",
    "ScoreVector",
    "Title",
    "AssetData",
    "AutoRemediationActions",
    "Category",
    "Inventory.Name",
    "Inventory.CiSource",
    "CloudAccount.Name",
    "CloudAccount.CloudProvider",
    "CreatedAt",
    "LastSeen",
    "Jira",
    "AzureDevops",
    "ServiceNowIncidents",
    "ServiceNowSiIncidents",
    "Monday",
    "Linear"
  ],
  "get_results_and_count": false,
  "full_graph_fetch": {
    "enabled": true
  },
  "debug_enable_bu_tags": true,
  "max_tier": 2
}'         --compressed

# B) ALERTAS DE DADOS SENSIVEIS ALTOS E CRITICOS IDENTIFICADOS EM X REPOSITORIOS: AMOUNT OF REPOSITORIES NEED TO BE COUNTED AS PART OF THE WORKFLOW
curl -X POST 'https://api.orcasecurity.io/api/serving-layer/query'         -H 'authority: api.orcasecurity.io'         -H 'accept: application/json, text/plain, */*'         -H 'accept-language: en-US,en;q=0.9'         -H 'authorization: TOKEN {{ORCA_API_TOKEN}}'         -H 'content-type: application/json'         --data-raw '{
  "query": {
    "models": [
      "Alert"
    ],
    "type": "object_set",
    "with": {
      "operator": "and",
      "type": "operation",
      "values": [
        {
          "key": "Labels",
          "values": [
            {
              "key": "Labels",
              "values": [
                "source:shiftleft"
              ],
              "type": "str",
              "operator": "in"
            }
          ],
          "type": "list",
          "operator": "any_match"
        },
        {
          "key": "Status",
          "values": [
            "open",
            "in_progress"
          ],
          "type": "str",
          "operator": "in"
        },
        {
          "key": "RiskLevel",
          "values": [
            "critical",
            "high"
          ],
          "type": "str",
          "operator": "in"
        },
        {
          "key": "Category",
          "values": [
            "Data at risk",
            "Data protection"
          ],
          "type": "str",
          "operator": "in"
        }
      ]
    }
  },
  "limit": 100,
  "start_at_index": 0,
  "order_by[]": [
    "-OrcaScore"
  ],
  "select": [
    "AlertId",
    "AlertType",
    "Status",
    "OrcaScore",
    "RiskLevel",
    "RuleSource",
    "RuleType",
    "ScoreVector",
    "Title",
    "AssetData",
    "AutoRemediationActions",
    "Category",
    "Inventory.Name",
    "Inventory.CiSource",
    "CloudAccount.Name",
    "CloudAccount.CloudProvider",
    "CreatedAt",
    "LastSeen",
    "Jira",
    "AzureDevops",
    "ServiceNowIncidents",
    "ServiceNowSiIncidents",
    "Monday",
    "Linear"
  ],
  "get_results_and_count": false,
  "full_graph_fetch": {
    "enabled": true
  },
  "debug_enable_bu_tags": true,
  "max_tier": 2
}'         --compressed

# C) REPOSITORIOS COM RECURSOS MAPEADOS DE INFRAESTRUTURA
curl -X POST 'https://api.orcasecurity.io/api/serving-layer/query'         -H 'authority: api.orcasecurity.io'         -H 'accept: application/json, text/plain, */*'         -H 'accept-language: en-US,en;q=0.9'         -H 'authorization: TOKEN {{ORCA_API_TOKEN}}'         -H 'content-type: application/json'         --data-raw '{
  "query": {
    "models": [
      "CodeRepository"
    ],
    "type": "object_set",
    "with": {
      "key": "Observations",
      "values": [
        {
          "key": "Observations",
          "values": [
            "deployed_assets"
          ],
          "type": "str",
          "operator": "in"
        }
      ],
      "type": "list",
      "operator": "any_match"
    }
  },
  "limit": 100,
  "start_at_index": 0,
  "order_by[]": [
    "-OrcaScore"
  ],
  "select": [
    "CiSource",
    "Name",
    "OrcaScore",
    "RiskLevel",
    "group_unique_id",
    "Exposure",
    "State",
    "Observations",
    "Tags",
    "ShiftleftProject.Name",
    "CodeLanguages",
    "Url"
  ],
  "get_results_and_count": false,
  "full_graph_fetch": {
    "enabled": true
  },
  "debug_enable_bu_tags": true,
  "max_tier": 2
}'         --compressed

