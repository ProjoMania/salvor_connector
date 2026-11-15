-- a copied/neutralized database must not answer Salvor with the production
-- pairing: wipe the token hash and allow list, disable the connector and drills
UPDATE salvor_connector_config
   SET token_hash = NULL,
       allowed_ips = NULL,
       paired_at = NULL,
       instance_id = NULL,
       enabled = false,
       drill_enabled = false;
