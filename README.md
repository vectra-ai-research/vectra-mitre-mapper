# Vectra MITRE Mapper

Vectra MITRE Mapper is a utility tool made available to allow Vectra platform users to generate real time interactive MITER map from the detections in their specific tenant. 

The utility levergaes Vectra SaaS API as the backbone which is used to connect and request detection information from the tenant. The tool also leverges MITRE Enterprise v14.1 (in current release) STIX data.

## Setup

1. Install tool
```
git clone git@github.com:vectra-ai-research/vectra-mitre-mapper.git
cd vectra-mitre-mapper
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```
2. Generate MITRE Coverage Layer
```
python3 VectraMitreMapper.py "https://tenant_url.portal.vectra.ai" "client_id" "client_secret" "optional_layer_name"
```

### Generating Client Credentials

To use the tool with a Vectra tenant, user will need to generate client credentials. This can be generated from the Vectra tenant directly by navigating to: 
```
Manage > API Clients > Add API Client > Select Role : "Security Analyst" > Generate Credentials
```