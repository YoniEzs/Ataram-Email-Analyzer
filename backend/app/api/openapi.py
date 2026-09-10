"""
OpenAPI 3.0 document for the ITgalya Email Analyzer API.

Hand-maintained: update this file when endpoint contracts change.
Served at /api/openapi.json and /api/v1/openapi.json.
"""

API_VERSION = '2.3'

OPENAPI_SPEC = {
    'openapi': '3.0.3',
    'info': {
        'title': 'ITgalya Email Analyzer API',
        'description': (
            'Local-first heuristic email security analysis with explicit '
            'evidence trust, independent DKIM verification, sender '
            'infrastructure enrichment, URL and attachment inspection, YARA, '
            'optional reputation integrations, and strict offline mode.'
        ),
        'version': API_VERSION,
        'license': {'name': 'MIT'},
    },
    'servers': [
        {'url': '/api/v1', 'description': 'Versioned API (preferred)'},
        {'url': '/api', 'description': 'Unversioned alias (backward compatible)'},
    ],
    'paths': {
        '/analyze': {
            'post': {
                'summary': 'Analyze an uploaded .eml or .msg email file',
                'requestBody': {
                    'required': True,
                    'content': {
                        'multipart/form-data': {
                            'schema': {
                                'type': 'object',
                                'required': ['emailfile'],
                                'properties': {
                                    'emailfile': {
                                        'type': 'string',
                                        'format': 'binary',
                                        'description': '.eml or .msg file (max 25MB)',
                                    },
                                    'abuseipdb_key': {
                                        'type': 'string',
                                        'format': 'password',
                                        'description': 'Optional BYOK key sent by the server to AbuseIPDB when enabled',
                                    },
                                    'virustotal_key': {
                                        'type': 'string',
                                        'format': 'password',
                                        'description': 'Optional BYOK key used for VirusTotal hash-only lookups when enabled',
                                    },
                                },
                            }
                        }
                    },
                },
                'responses': {
                    '200': {
                        'description': 'Full analysis result',
                        'content': {'application/json': {'schema': {'$ref': '#/components/schemas/AnalysisResult'}}},
                    },
                    '400': {'$ref': '#/components/responses/BadRequest'},
                    '413': {'$ref': '#/components/responses/TooLarge'},
                    '429': {'$ref': '#/components/responses/RateLimited'},
                },
            }
        },
        '/analyze/url': {
            'post': {
                'summary': 'Analyze a single URL for phishing indicators without visiting it',
                'requestBody': {
                    'required': True,
                    'content': {'application/json': {'schema': {
                        'type': 'object',
                        'required': ['url'],
                        'properties': {
                            'url': {
                                'type': 'string',
                                'maxLength': 4096,
                                'example': 'https://example.com/login',
                            },
                            'sender_domain': {
                                'type': 'string',
                                'maxLength': 253,
                                'example': 'example.com',
                            },
                        },
                    }}},
                },
                'responses': {
                    '200': {
                        'description': 'URL verdict',
                        'content': {'application/json': {'schema': {'$ref': '#/components/schemas/UrlResult'}}},
                    },
                    '400': {'$ref': '#/components/responses/BadRequest'},
                    '429': {'$ref': '#/components/responses/RateLimited'},
                },
            }
        },
        '/check/domain': {
            'post': {
                'summary': 'Check SPF/DMARC records and RDAP info for a domain',
                'description': 'Unavailable while strict offline mode is enabled.',
                'requestBody': {
                    'required': True,
                    'content': {'application/json': {'schema': {
                        'type': 'object',
                        'required': ['domain'],
                        'properties': {'domain': {'type': 'string', 'example': 'example.com'}},
                    }}},
                },
                'responses': {
                    '200': {'description': 'Domain records and registration info'},
                    '400': {'$ref': '#/components/responses/BadRequest'},
                    '429': {'$ref': '#/components/responses/RateLimited'},
                    '503': {'$ref': '#/components/responses/FeatureDisabled'},
                },
            }
        },
        '/check/ip': {
            'post': {
                'summary': 'Check IP reputation via AbuseIPDB',
                'description': 'Unavailable while strict offline mode or AbuseIPDB enrichment is disabled.',
                'requestBody': {
                    'required': True,
                    'content': {'application/json': {'schema': {
                        'type': 'object',
                        'required': ['ip'],
                        'properties': {
                            'ip': {'type': 'string', 'example': '8.8.8.8'},
                            'abuseipdb_key': {'type': 'string', 'format': 'password'},
                        },
                    }}},
                },
                'responses': {
                    '200': {'description': 'Reputation data'},
                    '400': {'$ref': '#/components/responses/BadRequest'},
                    '429': {'$ref': '#/components/responses/RateLimited'},
                    '503': {'$ref': '#/components/responses/FeatureDisabled'},
                },
            }
        },
    },
    'components': {
        'responses': {
            'BadRequest': {
                'description': 'Invalid input',
                'content': {'application/json': {'schema': {'$ref': '#/components/schemas/Error'}}},
            },
            'TooLarge': {
                'description': 'Upload exceeds the size limit',
                'content': {'application/json': {'schema': {'$ref': '#/components/schemas/Error'}}},
            },
            'RateLimited': {
                'description': 'Rate limit exceeded',
                'content': {'application/json': {'schema': {'$ref': '#/components/schemas/Error'}}},
            },
            'FeatureDisabled': {
                'description': 'The requested network-backed feature is disabled by configuration or strict offline mode',
                'content': {'application/json': {'schema': {'$ref': '#/components/schemas/Error'}}},
            },
        },
        'schemas': {
            'Error': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'},
                    'message': {'type': 'string'},
                },
            },
            'UrlResult': {
                'type': 'object',
                'properties': {
                    'url': {'type': 'string'},
                    'original_length': {'type': 'integer', 'minimum': 0},
                    'truncated': {'type': 'boolean'},
                    'domain': {'type': 'string'},
                    'issues': {'type': 'array', 'items': {'type': 'string'}},
                    'is_suspicious': {'type': 'boolean'},
                },
            },
            'AnalysisResult': {
                'type': 'object',
                'description': 'Complete analysis report',
                'properties': {
                    'timestamp': {'type': 'string', 'format': 'date-time'},
                    'conclusion': {
                        'type': 'object',
                        'description': (
                            'Concise summary of the key official artifacts '
                            'extracted from the message. Projected from '
                            'artifacts so the two never disagree. Values are '
                            'verbatim as received (RFC2047-decoded); the parsed '
                            'and normalized view is in artifacts.checklist.'
                        ),
                        'properties': {
                            'sender_address': {'type': 'string', 'nullable': True},
                            'subject': {'type': 'string', 'nullable': True},
                            'recipients': {
                                'type': 'string',
                                'nullable': True,
                                'description': 'Visible To/Cc recipients; BCC is never present in delivered headers',
                            },
                            'date': {'type': 'string', 'nullable': True},
                            'sending_server_ip': {'type': 'string', 'nullable': True},
                            'reverse_dns': {
                                'type': 'string',
                                'nullable': True,
                                'description': 'PTR record of the sending server IP when live enrichment is enabled',
                            },
                            'reply_to': {'type': 'string', 'nullable': True},
                        },
                    },
                    'headers': {'type': 'object'},
                    'artifacts': {
                        'type': 'object',
                        'description': (
                            'Analyst triage checklist and enrichment. Every '
                            'artifact and flag carries a trust value: '
                            'header_claim for uploaded-file claims, computed '
                            'for deterministic properties, and observed for '
                            'live DNS/RDAP facts. Only computed and observed '
                            'signals affect the risk score.'
                        ),
                        'properties': {
                            'schema_version': {'type': 'integer'},
                            'checklist': {
                                'type': 'object',
                                'description': (
                                    'Flat summary: sender address, subject, '
                                    'recipients, date, sending server IP, '
                                    'reverse DNS and Reply-To.'
                                ),
                            },
                            'sender': {'type': 'object'},
                            'subject': {'type': 'object'},
                            'recipients': {
                                'type': 'object',
                                'description': 'To and Cc split out, plus inferred envelope-recipient context when available.',
                            },
                            'date': {'type': 'object'},
                            'sending_server': {
                                'type': 'object',
                                'description': 'Originating IP with optional reverse-DNS and ASN/RDAP enrichment.',
                            },
                            'reverse_dns': {'type': 'object'},
                            'reply_to': {'type': 'object'},
                            'return_path': {'type': 'object'},
                            'message_id': {'type': 'object'},
                            'received_chain': {'type': 'array', 'items': {'type': 'object'}},
                            'authentication_advisory': {
                                'type': 'object',
                                'description': (
                                    'Advisory SPF re-evaluation. Display-only: '
                                    'its inputs come from forgeable headers, so '
                                    'it never affects the risk score.'
                                ),
                            },
                            'flags': {'type': 'array', 'items': {'type': 'object'}},
                            'enrichment_status': {
                                'type': 'object',
                                'description': 'Per-source outcome such as ok, disabled, skipped_no_public_ip, unavailable, or error.',
                            },
                        },
                    },
                    'authentication': {
                        'type': 'object',
                        'properties': {
                            'auth_results_raw': {'type': 'string', 'nullable': True},
                            'header_claims': {
                                'type': 'object',
                                'description': 'Display-only, attacker-controllable Authentication-Results claims',
                            },
                            'auth_analysis': {
                                'type': 'object',
                                'deprecated': True,
                                'description': 'Compatibility alias of header_claims',
                            },
                            'verification': {
                                'type': 'object',
                                'nullable': True,
                                'description': 'Independent DKIM verification when enabled; SPF/DMARC are not independently verifiable from an uploaded file alone',
                            },
                            'spf': {'type': 'string', 'nullable': True},
                            'dmarc': {'type': 'string', 'nullable': True},
                            'dkim': {'type': 'string', 'nullable': True},
                        },
                    },
                    'sender_info': {'type': 'object'},
                    'content': {'type': 'object'},
                    'urls': {'type': 'object'},
                    'attachments': {'type': 'object'},
                    'routing': {'type': 'object'},
                    'routing_forensics': {'type': 'object'},
                    'suspicions': {
                        'type': 'array',
                        'items': {
                            'type': 'object',
                            'properties': {
                                'category': {'type': 'string'},
                                'severity': {'type': 'string', 'enum': ['low', 'medium', 'high', 'critical']},
                                'message': {'type': 'string'},
                            },
                        },
                    },
                    'risk_assessment': {
                        'type': 'object',
                        'properties': {
                            'score': {'type': 'integer', 'minimum': 0, 'maximum': 100},
                            'level': {'type': 'string', 'enum': ['low', 'medium', 'high', 'critical']},
                            'verdict': {'type': 'string'},
                            'whitelist_applied': {'type': 'boolean'},
                            'factors': {
                                'type': 'array',
                                'description': 'Ordered breakdown of what contributed to the score',
                                'items': {
                                    'type': 'object',
                                    'properties': {
                                        'label': {'type': 'string'},
                                        'points': {'type': 'integer'},
                                        'severity': {'type': 'string', 'enum': ['info', 'low', 'medium', 'high', 'critical']},
                                        'detail': {'type': 'string'},
                                    },
                                },
                            },
                        },
                    },
                    'metadata': {
                        'type': 'object',
                        'required': ['filename', 'analyzed_at', 'version', 'offline_mode'],
                        'properties': {
                            'filename': {'type': 'string'},
                            'analyzed_at': {'type': 'string', 'format': 'date-time', 'nullable': True},
                            'version': {'type': 'string'},
                            'offline_mode': {
                                'type': 'boolean',
                                'description': 'True when strict offline mode disabled all network-backed enrichment for this analysis.',
                            },
                        },
                    },
                },
            },
        },
    },
}
