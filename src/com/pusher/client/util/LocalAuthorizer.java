package com.pusher.client.util;

import com.google.gson.JsonObject;
import com.pusher.client.AuthorizationFailureException;
import com.pusher.client.Authorizer;

import java.util.HashMap;

/**
 * Created by Ronel on 13/05/2014.
 */
public class LocalAuthorizer implements Authorizer {

    private HashMap<String, String> mHeaders = new HashMap<String, String>();
    private HashMap<String, String> mQueryStringParameters = new HashMap<String, String>();
    private final String appKey;
    private final String secretKey;

    public LocalAuthorizer(String appKey, String secretKey){
        this.appKey = appKey;
        this.secretKey = secretKey;
    }

    /**
     * This methods is for passing extra parameters authentication that needs to be added to query string.
     * @param queryStringParameters the query parameters
     */
    public void setQueryStringParameters(HashMap<String, String> queryStringParameters) {
        this.mQueryStringParameters = queryStringParameters;
    }

    /**
     * Set additional headers to be sent as part of the request.
     */
    public void setHeaders(HashMap<String, String> headers) {
        this.mHeaders = headers;
    }

    @Override
    public String authorize(String channelName, String socketId)
            throws AuthorizationFailureException {
        try {
            // Adding extra parameters supplied to be added to query string.
            String deviceId = mQueryStringParameters.get("device_id");
            String userId = mQueryStringParameters.get("user_id");

            JsonObject responseObject = new JsonObject();
            StringBuilder stringToSign = new StringBuilder()
                    .append(socketId)
                    .append(":")
                    .append(channelName);

            if (channelName.startsWith("presence-int")) {
                JsonObject userData = new JsonObject();
                userData.addProperty("user_id", userId);
                stringToSign.append(":").append(userData.toString());
                String signature = PusherUtils.hmacsha256Representation(stringToSign.toString(), secretKey);

                responseObject.addProperty("auth", appKey + ":" + signature);
                responseObject.addProperty("channel_data", userData.toString());
                return responseObject.toString();

            } else if (channelName.startsWith("presence-cmd")) {
                JsonObject userData = new JsonObject();
                userData.addProperty("user_id", deviceId);
                stringToSign.append(":").append(userData.toString());
                String signature = PusherUtils.hmacsha256Representation(stringToSign.toString(), secretKey);

                responseObject.addProperty("auth", appKey + ":" + signature);
                responseObject.addProperty("channel_data", userData.toString());
                return responseObject.toString();

            } else if (channelName.startsWith("private")) {
                String signature = PusherUtils.hmacsha256Representation(stringToSign.toString(), secretKey);

                responseObject.addProperty("auth", appKey + ":" + signature);
                return responseObject.toString();
            }

            return null;
        } catch (Exception e) {
            throw new AuthorizationFailureException(e);
        }
    }
}
