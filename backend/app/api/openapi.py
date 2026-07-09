"""
OpenAPI 3.0 document for the Email Analyzer API.

Hand-maintained: update this file when endpoint contracts change.
Served at /api/openapi.json and /api/v1/openapi.json.
"""

API_VERSION = '2.1'

OPENAPI_SPEC = {
    'openapi': '3.0.3',
    'info': {
        'title': 'Ataram Email Analyzer API',
        'description': (
            'Email security analysis: authentication (SPF/DKIM/DMARC, '
            'independent verification), sender reputation, URL and '
            'attachment inspection, YARA and VirusTotal integration.'
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
                                        'description': '.eml or .msg file (max 50MB)',
                                    },
                                    'abuseipdb_key': {
                                        'type': 'string',
                                        'description': 'Optional BYOK AbuseIPDB API key',
                                    },
                                    'virustotal_key': {
                                        'type': 'string',
                                        'description': 'Optional BYOK VirusTotal API key',
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
                'summary': 'Analyze a single URL for phishing indicators',
                'requestBody': {
                    'required': True,
                    'content': {'application/json': {'schema': {
                        'type': 'object',
                        'required': ['url'],
                        'properties': {
                            'url': {'type': 'string', 'example': 'https://example.com/login'},
                            'sender_domain': {'type': 'string', 'example': 'example.com'},
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
                'summary': 'Check SPF/DMARC records and WHOIS info for a domain',
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
                },
            }
        },
        '/check/ip': {
            'post': {
                'summary': 'Check IP reputation via AbuseIPDB',
                'requestBody': {
                    'required': True,
                    'content': {'application/json': {'schema': {
                        'type': 'object',
                        'required': ['ip'],
                        'properties': {
                            'ip': {'type': 'string', 'example': '203.0.113.5'},
                            'abuseipdb_key': {'type': 'string'},
                        },
                    }}},
                },
                'responses': {
                    '200': {'description': 'Reputation data'},
                    '400': {'$ref': '#/components/responses/BadRequest'},
                    '429': {'$ref': '#/components/responses/RateLimited'},
                    '503': {'description': 'Feature disabled'},
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
                    'headers': {'type': 'object'},
                    'authentication': {
                        'type': 'object',
                        'properties': {
                            'auth_results_raw': {'type': 'string', 'nullable': True},
                            'auth_analysis': {'type': 'object'},
                            'verification': {
                                'type': 'object',
                                'nullable': True,
                                'description': 'Independent SPF/DKIM verification results',
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
                        },
                    },
                    'metadata': {'type': 'object'},
                },
            },
        },
    },
}
