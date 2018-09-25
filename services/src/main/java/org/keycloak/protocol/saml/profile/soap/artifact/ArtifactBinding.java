package org.keycloak.protocol.saml.profile.soap.artifact;

import org.jboss.logging.Logger;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.dom.saml.v2.protocol.ArtifactResponseType;
import org.keycloak.dom.saml.v2.protocol.ResponseType;
import org.keycloak.dom.saml.v2.protocol.StatusCodeType;
import org.keycloak.dom.saml.v2.protocol.StatusType;
import org.keycloak.protocol.saml.profile.soap.util.Soap;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.DocumentUtil;
import org.keycloak.saml.common.util.StaxUtil;
import org.keycloak.saml.processing.core.saml.v2.common.IDGenerator;
import org.keycloak.saml.processing.core.saml.v2.util.XMLTimeUtil;
import org.keycloak.saml.processing.core.saml.v2.writers.SAMLResponseWriter;
import org.w3c.dom.Document;

import javax.ws.rs.core.CacheControl;
import javax.ws.rs.core.Response;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Stream;

public class ArtifactBinding {

    private static final Logger logger = Logger.getLogger(ArtifactBinding.class);

    /** SAML 2 artifact type code (0x0004). */
    private static final byte[] TYPE_CODE = { 0, 4 };

    public Map<String, Document> responseMap = new HashMap<>();

    private static ArtifactBinding singleton;

    private ArtifactBinding(){}

    public static ArtifactBinding getSingletonInstance() {
        if (singleton == null) {
            singleton = new ArtifactBinding();
        }
        return singleton;
    }

    public String saveArtifactResponse(ResponseType samlResponse, String entityId) throws Exception {
        String artifactB64 = buildArtifact(entityId);
        responseMap.put(artifactB64, convert(createAssertionResponse(samlResponse)));
        return artifactB64;
    }

    private ArtifactResponseType createAssertionResponse(ResponseType samlResponse) throws ConfigurationException {
        ArtifactResponseType artifactResponse = new ArtifactResponseType(IDGenerator.create("ID_"),
                XMLTimeUtil.getIssueInstant());
        artifactResponse.setIssuer(samlResponse.getIssuer());

        // Status
        StatusType statusType = new StatusType();
        StatusCodeType statusCodeType = new StatusCodeType();
        statusCodeType.setValue(JBossSAMLURIConstants.STATUS_SUCCESS.getUri());
        statusType.setStatusCode(statusCodeType);

        artifactResponse.setStatus(statusType);
        artifactResponse.setAny(samlResponse);
        return artifactResponse;
    }

    /**
     * Convert a SAML2 Response into a Document
     *
     * @param responseType
     *
     * @return
     *
     * @throws ParsingException
     * @throws ConfigurationException
     * @throws ProcessingException
     */
    private Document convert(ArtifactResponseType responseType) throws ProcessingException, ConfigurationException,
            ParsingException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        SAMLResponseWriter writer = new SAMLResponseWriter(StaxUtil.getXMLStreamWriter(bos));
        writer.write(responseType);
        return DocumentUtil.getDocument(new ByteArrayInputStream(bos.toByteArray()));
    }

    public Response buildArtifactResponse(String artifact) {
        Document artifactResponseDocument = responseMap.remove(artifact);
        logger.debug("Returning ArtifactResponse for artifact: " + artifact);
        return buildAuthenticatedResponse(artifactResponseDocument);
    }

    public Document getArtifactResponse(String artifact) {
        return responseMap.get(artifact);
    }

    private Response buildAuthenticatedResponse(Document artifactResponseDocument) {

        try {
            if (artifactResponseDocument == null) {
                throw new Exception("Artifact doesn't exist");
            }
            Soap.SoapMessageBuilder messageBuilder = Soap.createMessage();

            messageBuilder.addToBody(artifactResponseDocument);

            return messageBuilder.build();
        } catch (Exception e) {
            String reason = "An error occurred while resolving the artifact";
            String detail = e.getMessage();

            if (detail == null) {
                detail = reason;
            }
            return Soap.createFault().reason(reason).detail(detail).build();
        }
    }

    public Response artifactRedirect(String redirectUri, String artifact)  {
        KeycloakUriBuilder builder = KeycloakUriBuilder.fromUri(redirectUri)
                .replaceQuery(null)
                .queryParam("SAMLart", artifact);
        URI uri = builder.build();
        CacheControl cacheControl = new CacheControl();
        cacheControl.setNoCache(true);
        return Response.status(302).location(uri)
                .header("Pragma", "no-cache")
                .header("Cache-Control", "no-cache, no-store").build();
    }

    private String buildArtifact(String entityId) throws Exception {
        try {
            SecureRandom handleGenerator = SecureRandom.getInstance("SHA1PRNG");
            byte[] trimmedIndex = new byte[2];

            MessageDigest sha1Digester = MessageDigest.getInstance("SHA-1");
            byte[] source = sha1Digester.digest(entityId.getBytes());

            byte[] assertionHandle;
            assertionHandle = new byte[20];
            handleGenerator.nextBytes(assertionHandle);

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bos.write(TYPE_CODE);
            bos.write(trimmedIndex);
            bos.write(source);
            bos.write(assertionHandle);

            byte[] artifact = bos.toByteArray();

            return Base64.getEncoder().encodeToString(artifact);
        } catch (NoSuchAlgorithmException e) {
            logger.error("JVM does not support required cryptography algorithms: SHA-1/SHA1PRNG.", e);
            throw new Exception("JVM does not support required cryptography algorithms: SHA-1/SHA1PRNG.");
        }
    }

}
