insert_masterscript = "INSERT INTO ceh_itsm.ceh_service_request_master (sr_category_id, submitter, assigned_to_group_id, details, master_reference_id, itsm_ci_id, sys_id, created_on, state_id, updated_on, sub_category, tenant_id, short_description, processed_state, vstatus, attachment, metadata, comments) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
masterscript_param = (sr_category_id_psqlScript, submitter, assigned_to_group_id_psqlScript, ACTION_REQUIRED, master_reference_id, itsm_ci_id, sys_id, created_on, state_id_psqlScript, updated_on, sub_category_id_psqlScript, tenantid, short_description, processed_state, vstatus, attachment, metadata, jobnames, comments)