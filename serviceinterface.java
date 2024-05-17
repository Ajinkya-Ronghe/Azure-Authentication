package com.infy.ceh.management.dtcc.service;

import com.infy.ceh.management.dtcc.exception.CEHServiceException;
import org.json.JSONObject;

import java.util.List;

public interface DTCSSSPService {

    /**
     * Adds a new SSP request using the provided JSON object.
     * 
     * @param sspJson JSONObject containing the SSP request details.
     * @throws CEHServiceException if there is an error processing the request.
     */
    void addSSPRequest(JSONObject sspJson) throws CEHServiceException;

    /**
     * Retrieves the status of an SSP request based on the unique identifier.
     * 
     * @param sspUid Unique identifier of the SSP request.
     * @return String representing the status of the SSP request.
     * @throws CEHServiceException if there is an error retrieving the status.
     */
    String getSSPRequestStatusById(String sspUid) throws CEHServiceException;

    /**
     * Authenticates the user using the provided unique identifier and password.
     * 
     * @param sspUid Unique identifier of the user.
     * @param password Password of the user.
     * @return boolean True if authentication is successful, otherwise false.
     * @throws CEHServiceException if there is an authentication failure.
     */
    boolean authenticate(String sspUid, String password) throws CEHServiceException;

    /**
     * Retrieves a list of all SSP details.
     * 
     * @return List of SSPDTO objects each representing details of an SSP.
     * @throws CEHServiceException if there is an error retrieving the details.
     */
    List<SSPDTO> getSSPDetails() throws CEHServiceException;

    /**
     * Inserts or updates SSP details based on the provided list of SSPDTO objects.
     * 
     * @param sspDetailsList List of SSPDTO objects to be upserted.
     * @throws CEHServiceException if there is an error during the upsert operation.
     */
    void upsertSSPDetails(List<SSPDTO> sspDetailsList) throws CEHServiceException;

}
