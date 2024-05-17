package com.infy.ceh.management.dtcc.service.impl;

import com.infy.ceh.management.dtcc.exception.CEHServiceException;
import com.infy.ceh.management.dtcc.service.DTCSSSPService;
import com.infy.ceh.management.dtcc.ssp.dto.SSPDTO;
import com.infy.ceh.management.identity.domain.CEHUser;
import com.infy.ceh.management.identity.service.UserService;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class DTCSSSPServiceImpl implements DTCSSSPService {

    @Autowired
    private SSPDAOImpl sspDaoImpl;

    @Autowired
    private UserService userService;

    private static final Logger logger = LoggerFactory.getLogger(DTCSSSPServiceImpl.class);

    @Override
    public void addSSPRequest(JSONObject sspJson) throws CEHServiceException {
        logger.debug("Inside addSSPRequest");
        try {
            sspDaoImpl.insertRequestDetails(sspJson);
        } catch (Exception e) {
            logger.error("Exception while inserting SSP details into database: {}", e.getMessage(), e);
            throw new CEHServiceException("Error inserting SSP request: " + e.getMessage(), e);
        }
    }

    @Override
    public String getSSPRequestStatusById(String sspUid) throws CEHServiceException {
        logger.debug("Inside getSSPRequestStatusById for UID: {}", sspUid);
        try {
            return sspDaoImpl.getSSPRequestStatusById(sspUid);
        } catch (Exception e) {
            logger.error("Error in getSSPRequestStatusById for UID: {}: {}", sspUid, e.getMessage(), e);
            throw new CEHServiceException("Unable to retrieve SSP status: " + e.getMessage(), e);
        }
    }

    @Override
    public boolean authenticate(String sspUid, String password) throws CEHServiceException {
        logger.debug("Inside authenticate for UID: {}", sspUid);
        try {
            CEHUser user = userService.fetchUserById(sspUid);
            if (user != null && password.equals(user.getPassword())) {
                logger.info("Authentication successful for UID: {}", sspUid);
                return true;
            } else {
                logger.warn("Authentication failed for UID: {}", sspUid);
                return false;
            }
        } catch (Exception e) {
            logger.error("Error while authenticating UID: {}: {}", sspUid, e.getMessage(), e);
            throw new CEHServiceException("Authentication error: " + e.getMessage(), e);
        }
    }

    @Override
    public List<SSPDTO> getSSPDetails() throws CEHServiceException {
        logger.debug("Inside getSSPDetails");
        try {
            return sspDaoImpl.getSSPDetails();
        } catch (Exception e) {
            logger.error("Error in getSSPDetails: {}", e.getMessage(), e);
            throw new CEHServiceException("Unable to fetch SSP details: " + e.getMessage(), e);
        }
    }

    @Override
    public void upsertSSPDetails(List<SSPDTO> sspDetailsList) throws CEHServiceException {
        logger.debug("Inside upsertSSPDetails");
        try {
            for (SSPDTO sspDTO : sspDetailsList) {
                sspDaoImpl.upsertSSPDetailsToRequestMaster(sspDTO);
            }
        } catch (Exception e) {
            logger.error("Error in upsertSSPDetails: {}", e.getMessage(), e);
            throw new CEHServiceException("Error during upsert operation: " + e.getMessage(), e);
        }
    }
}
