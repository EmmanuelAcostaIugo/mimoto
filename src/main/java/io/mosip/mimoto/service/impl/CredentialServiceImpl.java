package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.exception.InvalidCredentialResourceException;
import io.mosip.mimoto.exception.VCVerificationException;
import io.mosip.mimoto.model.QRCodeType;
import io.mosip.mimoto.service.CredentialRequestService;
import io.mosip.mimoto.service.CredentialService;
import io.mosip.mimoto.service.CredentialVerifierService;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.service.CredentialPDFGeneratorService;
import io.mosip.mimoto.util.RestApiClient;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;

import static io.mosip.mimoto.exception.ErrorConstants.SIGNATURE_VERIFICATION_EXCEPTION;

@Slf4j
@Service
public class CredentialServiceImpl implements CredentialService {

    @Autowired
    IssuersService issuersService;

    @Autowired
    DataShareServiceImpl dataShareService;

    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    RestApiClient restApiClient;

    @Autowired
    private CredentialPDFGeneratorService credentialPDFGeneratorService;

    @Autowired
    private CredentialVerifierService credentialVerifierService;

    @Autowired
    private CredentialRequestService credentialRequestService;


    @Override
    public ByteArrayInputStream downloadCredentialAsPDF(String issuerId, String credentialType, TokenResponseDTO response, String credentialValidity, String locale) throws Exception {
        log.info("Token attributes in downloadCredentialAsPDF - id_token: {}, token_type: {}, access_token: {}, expires_in: {}, scope: {}, c_nonce: {}", 
                response.getId_token(), response.getToken_type(), response.getAccess_token(), 
                response.getExpires_in(), response.getScope(), response.getC_nonce());
        log.info("c_nonce_expires_in: {}", response.getC_nonce_expires_in());
        if(response.getC_nonce_expires_in() != null) {
            log.info("c_nonce_expires_in is not null");
        } else {
            log.info("c_nonce_expires_in is null");
            response.setC_nonce_expires_in(18000);
            log.info("c_nonce_expires_in set to 18000");
        }
        IssuerDTO issuerDTO = issuersService.getIssuerDetails(issuerId);
        CredentialIssuerConfiguration credentialIssuerConfiguration = issuersService.getIssuerConfiguration(issuerId);
        CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse = new CredentialIssuerWellKnownResponse(
                credentialIssuerConfiguration.getCredentialIssuer(),
                credentialIssuerConfiguration.getAuthorizationServers(),
                credentialIssuerConfiguration.getCredentialEndPoint(),
                credentialIssuerConfiguration.getCredentialConfigurationsSupported());
        CredentialsSupportedResponse credentialsSupportedResponse = credentialIssuerWellKnownResponse.getCredentialConfigurationsSupported().get(credentialType);
        VCCredentialRequest vcCredentialRequest = credentialRequestService.buildRequest(issuerDTO, credentialIssuerWellKnownResponse, credentialsSupportedResponse, response.getC_nonce(), null, null, false
        );
        VCCredentialResponse vcCredentialResponse = downloadCredential(credentialIssuerWellKnownResponse.getCredentialEndPoint(), vcCredentialRequest, response.getAccess_token());
        log.info("VC Credential Response is -> " + vcCredentialResponse);
        boolean verificationStatus = issuerId.toLowerCase().contains("mock") || credentialVerifierService.verify(vcCredentialResponse);
        log.info("Verification Status is -> " + verificationStatus);
        if (verificationStatus) {
            String dataShareUrl = QRCodeType.OnlineSharing.equals(issuerDTO.getQr_code_type()) ? dataShareService.storeDataInDataShare(objectMapper.writeValueAsString(vcCredentialResponse), credentialValidity) : "";
            log.info("Data Share URL is -> " + dataShareUrl);
            return credentialPDFGeneratorService.generatePdfForVerifiableCredentials(credentialType, vcCredentialResponse, issuerDTO, credentialsSupportedResponse, dataShareUrl, credentialValidity, locale);
        }
        throw new VCVerificationException(SIGNATURE_VERIFICATION_EXCEPTION.getErrorCode(),
                SIGNATURE_VERIFICATION_EXCEPTION.getErrorMessage());
    }

    @Override
    public VCCredentialResponse downloadCredential(String credentialEndpoint, VCCredentialRequest vcCredentialRequest, String accessToken) throws InvalidCredentialResourceException {
        log.info("VC Credential Request is -> " + vcCredentialRequest);
        log.info("Credential Endpoint is -> " + credentialEndpoint);
        VCCredentialResponse vcCredentialResponse = restApiClient.postApi(credentialEndpoint, MediaType.APPLICATION_JSON,
                vcCredentialRequest, VCCredentialResponse.class, accessToken);
        log.debug("VC Credential Response is -> " + vcCredentialResponse);
        if (vcCredentialResponse == null)
            throw new InvalidCredentialResourceException("VC Credential Issue API not accessible");
        vcCredentialResponse.setFormat(vcCredentialRequest.getFormat());
        
        // Ensure type field is set if it's null
        if (vcCredentialResponse.getCredential().getType() == null || vcCredentialResponse.getCredential().getType().isEmpty()) {
            log.warn("Type field is null or empty in credential response, setting from request definition");
            vcCredentialResponse.getCredential().setType(vcCredentialRequest.getCredentialDefinition().getType());
        }
        
        return vcCredentialResponse;
    }


}
