# A) collect all vulnerabilities
curl -X POST 'https://api.orcasecurity.io/api/serving-layer/query' \
  -H 'authority: api.orcasecurity.io' \
  -H 'accept: application/json, text/plain, */*' \
  -H 'accept-language: en-US,en;q=0.9' \
  -H "authorization: TOKEN ${ORCA_TOKEN}" \
  -H 'content-type: application/json' \
  --data-raw '{
  "query": {
    "models": [
      "VulnerabilityV2"
    ],
    "type": "object_set"
  },
  "limit": 1,
  "start_at_index": 0,
  "order_by[]": [
    "-CvssScore"
  ],
  "select": [],
  "get_results_and_count": true,
  "full_graph_fetch": {
    "enabled": true
  },
  "debug_enable_bu_tags": true,
  "max_tier": 2
}' \
  --compressed

# response:
{"status":"success","data":[{"id":"3281ec1f-31a8-c881-d181-1b924a1f97c4","name":"CVE-2025-68121 - stdlib-1.24.2","type":"VulnerabilityV2","data":{"CvssScore":{"value":10},"FirstSeen":{"value":"2026-02-09T13:15:04+00:00"},"CvssSource":{"value":"Ubuntu v3"},"CveId":{"value":"CVE-2025-68121"},"PatchedVersions":{"value":["1.24.13","1.25.7","1.26.0-rc.3"]},"EpssPercentile":{"value":4},"HasExploit":{"value":false},"Name":{"value":"CVE-2025-68121 - stdlib-1.24.2"},"CisaKev":{"value":false},"SourceLink":{"value":"https://ubuntu.com/security/CVE-2025-68121"},"CvssSeverity":{"value":"CRITICAL"},"Description":{"value":"During session resumption in crypto/tls, if the underlying Config has its ClientCAs or RootCAs fields mutated between the initial handshake and the resumed handshake, the resumed handshake may succeed when it should have failed. This may happen when a user calls Config.Clone and mutates the returned Config, or uses Config.GetConfigForClient. This can cause a client to resume a session with a server that it would not have resumed with during the initial handshake, or cause a server to resume a..."},"PatchAvailable":{"value":"Yes"},"PatchReleaseDate":{"value":"2026-02-04T22:00:00+00:00"},"EpssProbability":{"value":0.018},"Trending":{"value":"No"},"CvssVector":{"value":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},"bu_tags":{"value":",-7721881147284212895,-3433765631334502247,8435438298388360142,3186963892758927136,-7098908799675028497,1069540321240315821,-1801142155936603940,7711202956547505332,-4459486838759696594,-557798895365950916,7730390857430590933,1543090229481909909,"}}}],"total_items":249899}

# B) collect vulnerabilities with fix available:
curl -X POST 'https://api.orcasecurity.io/api/serving-layer/query' \
  -H 'authority: api.orcasecurity.io' \
  -H 'accept: application/json, text/plain, */*' \
  -H 'accept-language: en-US,en;q=0.9' \
  -H "authorization: TOKEN ${ORCA_TOKEN}" \
  -H 'content-type: application/json' \
  --data-raw '{
  "query": {
    "models": [
      "VulnerabilityV2"
    ],
    "type": "object_set",
    "with": {
      "key": "PatchAvailable",
      "values": [
        "Yes"
      ],
      "type": "str",
      "operator": "in"
    }
  },
  "limit": 1,
  "start_at_index": 0,
  "order_by[]": [
    "-CvssScore"
  ],
  "select": [],
  "get_results_and_count": true,
  "full_graph_fetch": {
    "enabled": true
  },
  "debug_enable_bu_tags": true,
  "max_tier": 2
}' \
  --compressed

# for high ones use this:
"query": {
    "models": [
      "VulnerabilityV2"
    ],
    "type": "object_set",
    "with": {
      "operator": "and",
      "type": "operation",
      "values": [
        {
          "key": "PatchAvailable",
          "values": [
            "Yes"
          ],
          "type": "str",
          "operator": "in"
        },
        {
          "key": "CvssSeverity",
          "values": [
            "HIGH"
          ],
          "type": "str",
          "operator": "in"
        }
      ]
    }
  }

# for critical ones use this:
"query": {
    "models": [
      "VulnerabilityV2"
    ],
    "type": "object_set",
    "with": {
      "operator": "and",
      "type": "operation",
      "values": [
        {
          "key": "PatchAvailable",
          "values": [
            "Yes"
          ],
          "type": "str",
          "operator": "in"
        },
        {
          "key": "CvssSeverity",
          "values": [
            "CRITICAL"
          ],
          "type": "str",
          "operator": "in"
        }
      ]
    }
  }
