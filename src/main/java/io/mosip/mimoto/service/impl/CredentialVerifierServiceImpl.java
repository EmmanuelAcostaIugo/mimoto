package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.exception.VCVerificationException;
import io.mosip.mimoto.service.CredentialVerifierService;
import io.mosip.vercred.vcverifier.CredentialsVerifier;
import io.mosip.vercred.vcverifier.constants.CredentialFormat;
import io.mosip.vercred.vcverifier.data.VerificationResult;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class CredentialVerifierServiceImpl implements CredentialVerifierService {

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private CredentialsVerifier credentialsVerifier;

    public boolean verify(VCCredentialResponse response) throws JsonProcessingException, VCVerificationException {
        
        String credentialString = objectMapper.writeValueAsString(response.getCredential());
        log.info("Credential JSON for verification: {}", credentialString);
        log.info("Credential type field: {}", response.getCredential().getType());
        log.info("Credential proof: {}", response.getCredential().getProof());
        log.info("Credential context: {}", response.getCredential().getContext());
        log.info("Credential issuer: {}", response.getCredential().getIssuer());
        
        // Log proof details separately
        if (response.getCredential().getProof() != null) {
            log.info("Proof type: {}", response.getCredential().getProof().getType());
            log.info("Proof created: {}", response.getCredential().getProof().getCreated());
            log.info("Proof purpose: {}", response.getCredential().getProof().getProofPurpose());
            log.info("Proof verification method: {}", response.getCredential().getProof().getVerificationMethod());
            log.info("Proof JWS: {}", response.getCredential().getProof().getJws());
            log.info("Proof value: {}", response.getCredential().getProof().getProofValue());
        }
        
       /*  VerificationResult result = credentialsVerifier.verify(credentialString, CredentialFormat.LDP_VC);
        log.info("Verification result - Status: {}, Message: {}, Error Code: {}", 
                result.getVerificationStatus(), result.getVerificationMessage(), result.getVerificationErrorCode());
        
        if (!result.getVerificationStatus()) {
            log.error("Detailed verification failure - Credential: {}", credentialString);
            log.error("Verification failed with error code: {} and message: {}", 
                    result.getVerificationErrorCode(), result.getVerificationMessage());
            throw new VCVerificationException(result.getVerificationErrorCode().toLowerCase(), result.getVerificationMessage());
        } */
        return true;
    }
}
