# Vectra MITRE Mapper

This tool allows you to connect to a Vectra SaaS tenant and generate a real time interactive MITER map from the detections in the tenant. 

## Usage
1. Install requirements
`pip install -r requirements.txt`
2. Open `/Modules/APIAuth.py` file in editor and credential info
- Enter `tenant_url`
- Enter `client_id`
- Enter `client_secret`
2. Save APIAuth.py with the added details
3. Run the tool.
`python3 VectraMitreMapper.py`