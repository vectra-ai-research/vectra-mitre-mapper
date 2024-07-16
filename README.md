# Vectra MITRE Mapper

Vectra MITRE Mapper is a utility tool made available to allow Vectra platform users to generate real time interactive MITRE map from the detections in their specific tenant. 

The tool levergaes Vectra SaaS API as the backbone which is used to connect and request detection information from the tenant. The tool also leverges MITRE Enterprise v15.1 (in current release) STIX data.

## Setup

1. Install tool
```
git clone git@github.com:vectra-ai-research/vectra-mitre-mapper.git
cd vectra-mitre-mapper
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```
2. Generate Detections MITRE Map
```
# for active detections
python3 VectraMitreMapper.py -url "https://tenant_url.portal.vectra.ai/" -client "client_id" -secret "client_secret" -name "optional_layer_name" -state "active"

# for all detections
python3 VectraMitreMapper.py -url "https://tenant_url.portal.vectra.ai/" -client "client_id" -secret "client_secret" -name "optional_layer_name" -state "all"

# help 
python3 VectraMitreMapper.py -h
```

### Generating Client Credentials

To use the tool with a Vectra tenant, user will need to generate client credentials. This can be generated from the Vectra tenant directly by navigating to: 
```
Manage > API Clients > Add API Client > Select Role : "Security Analyst" > Generate Credentials
```