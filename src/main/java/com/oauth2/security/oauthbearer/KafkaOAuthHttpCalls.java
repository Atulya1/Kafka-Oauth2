package com.oauth2.security.oauthbearer;
/*
Author - Atul Kumar
*/
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

import org.apache.kafka.common.utils.Time;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

public class KafkaOAuthHttpCalls {

    private static final Logger log = LoggerFactory.getLogger(KafkaOAuthHttpCalls.class);

    private static String OAUTH_LOGIN_SERVER;
    private static String OAUTH_LOGIN_ENDPOINT;
    private static String OAUTH_LOGIN_GRANT_TYPE;
    private static String OAUTH_LOGIN_SCOPE;

    private static String OAUTH_INTROSPECT_SERVER;
    private static String OAUTH_INTROSPECT_ENDPOINT;

    private static String OAUTH_LOGIN_AUTHORIZATION;
    private static String OAUTH_INTROSPECT_AUTHORIZATION;

    private static boolean OAUTH_ACCEPT_UNSECURE_SERVER;
    private static boolean OAUTH_WITH_SSL;
    private static Time time = Time.SYSTEM;

    public static void acceptUnsecureServer(){
        if(OAUTH_ACCEPT_UNSECURE_SERVER){
            TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                            return null;
                        }
                        public void checkClientTrusted(
                                java.security.cert.X509Certificate[] certs, String authType) {
                        }
                        public void checkServerTrusted(
                                java.security.cert.X509Certificate[] certs, String authType) {
                        }
                    }
            };
            try{
                SSLContext sc = SSLContext.getInstance("SSL");
                sc.init(null, trustAllCerts, new java.security.SecureRandom());
                HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            }catch(NoSuchAlgorithmException e){
                log.error("at acceptUnsecureServer :", e);
            }catch(KeyManagementException e){
                log.error("at acceptUnsecureServer :", e);
            }
        }
    }

    public static KafkaOAuthBearerTokenJwt login(Map<String, String> options) {
        KafkaOAuthBearerTokenJwt result = null;
        try {
            setPropertyValues(options);
            acceptUnsecureServer();
            long callTime = time.milliseconds();

            //Mount POST data
            String grantType = "grant_type=" + OAUTH_LOGIN_GRANT_TYPE;
            String scope = "scope=" + OAUTH_LOGIN_SCOPE;
            String postDataStr = grantType + "&" + scope;
            String OAUTH_LOGIN_AUTH = OAUTH_LOGIN_AUTHORIZATION.replaceAll("^\"|\"$", "");
            log.info("Try to login with oauth!");
            log.info("Oauth Login Server:" + OAUTH_LOGIN_SERVER);
            log.info("Oauth Login EndPoint:" + OAUTH_LOGIN_ENDPOINT);
            log.info("Oauth Login Authorization:" + OAUTH_LOGIN_AUTH);

            Map<String, Object> resp = null;
            if(OAUTH_WITH_SSL){
                resp = doHttpsCall(OAUTH_LOGIN_SERVER + OAUTH_LOGIN_ENDPOINT, postDataStr, OAUTH_LOGIN_AUTH);
            }else{
                resp = doHttpCall(OAUTH_LOGIN_SERVER + OAUTH_LOGIN_ENDPOINT, postDataStr, OAUTH_LOGIN_AUTH);
            }

            if(!resp.isEmpty()){
                String accessToken = (String) resp.get("access_token");
                long expiresIn = ((Integer) resp.get("expires_in")).longValue();
                String clientId = (String) resp.get("client_id");
                result = new KafkaOAuthBearerTokenJwt(accessToken, expiresIn, callTime, clientId);
            } else {
                throw new Exception("Null response at login");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    private static void setPropertyValues(Map<String, String> options) {
        OAUTH_LOGIN_SERVER = (String) getPropertyValue(options, "OAUTH_LOGIN_SERVER", "");
        OAUTH_LOGIN_ENDPOINT = (String) getPropertyValue(options, "OAUTH_LOGIN_ENDPOINT", "");
        OAUTH_LOGIN_GRANT_TYPE = (String) getPropertyValue(options, "OAUTH_LOGIN_GRANT_TYPE", "");
        OAUTH_LOGIN_SCOPE = (String) getPropertyValue(options, "OAUTH_LOGIN_SCOPE", "");

        OAUTH_INTROSPECT_SERVER = (String) getPropertyValue(options, "OAUTH_INTROSPECT_SERVER", "");
        OAUTH_INTROSPECT_ENDPOINT = (String) getPropertyValue(options, "OAUTH_INTROSPECT_ENDPOINT", "");

        OAUTH_LOGIN_AUTHORIZATION = (String) getPropertyValue(options, "OAUTH_AUTHORIZATION", "");
        OAUTH_INTROSPECT_AUTHORIZATION = (String) getPropertyValue(options, "OAUTH_INTROSPECT_AUTHORIZATION", "");

        OAUTH_ACCEPT_UNSECURE_SERVER = (Boolean) getPropertyValue(options, "OAUTH_ACCEPT_UNSECURE_SERVER", false);
        OAUTH_WITH_SSL = (Boolean) getPropertyValue(options, "OAUTH_WITH_SSL", true);
    }

    public static KafkaOAuthBearerTokenJwt introspectBearer(Map<String, String> options, String accessToken){
        KafkaOAuthBearerTokenJwt result = null;
        try {
            setPropertyValues(options);
            //Mount POST data
            String token = "token=" +  accessToken;

            log.info("Try to introspect with oauth!");
            System.out.println("Oauth Introspect Server:" + OAUTH_INTROSPECT_SERVER);
            System.out.println("Oauth Introspect EndPoint:" + OAUTH_INTROSPECT_ENDPOINT);
            System.out.println("Oauth Authorization:" + OAUTH_INTROSPECT_AUTHORIZATION);
            String OAUTH_INTROSPECT_AUTH = OAUTH_INTROSPECT_AUTHORIZATION.replaceAll("^\"|\"$", "");
            Map<String, Object> resp = null;
            if(OAUTH_WITH_SSL){
                resp = doHttpsCall(OAUTH_INTROSPECT_SERVER + OAUTH_INTROSPECT_ENDPOINT, token, OAUTH_INTROSPECT_AUTH);
            }else{
                resp = doHttpCall(OAUTH_INTROSPECT_SERVER + OAUTH_INTROSPECT_ENDPOINT, token, OAUTH_INTROSPECT_AUTH);
            }
            if(!resp.isEmpty()){
                if((boolean) resp.get("active")){
                    result = new KafkaOAuthBearerTokenJwt(resp, accessToken);
                }else{
                    throw new Exception("Expired Token");
                }
            }
        }catch (Exception e){
            e.printStackTrace();
        }
        return result;
    }

    private static Map<String, Object> doHttpsCall(String urlStr, String postParameters, String oauthToken){
        try{
            acceptUnsecureServer();
            OkHttpClient client = new OkHttpClient();
			MediaType mediaType = MediaType.parse("application/x-www-form-urlencoded");
			RequestBody body = RequestBody.create(mediaType, postParameters);
			System.out.println("https://" + urlStr);
			System.out.println(postParameters);
			Request request = new Request.Builder()
			  .url("https://" + urlStr)
			  .method("POST", body)
			  .addHeader("Content-Type", "application/x-www-form-urlencoded")
			  .addHeader("Authorization", oauthToken)
			  .build();
				Response response = client.newCall(request).execute();
				String responseBody = response.body().string();
				if (response.code() == 200) {
	                return handleJsonResponse(responseBody);
	            }else {
	                throw new Exception("Return code " + response.code());
	            }
        } catch(Exception e) {
        	
        }
        return null;
    }
    private static Map<String, Object> doHttpCall(String urlStr, String postParameters, String oauthToken){
        try{
            acceptUnsecureServer();
            log.info("doHttpCall ->");
            OkHttpClient client = new OkHttpClient();
			MediaType mediaType = MediaType.parse("application/x-www-form-urlencoded");
			RequestBody body = RequestBody.create(mediaType, postParameters);
			System.out.println("https://" + urlStr+postParameters);
			System.out.println(oauthToken);
			Request request = new Request.Builder()
			  .url("https://" + urlStr)
			  .method("POST", body)
			  .addHeader("Content-Type", "application/x-www-form-urlencoded")
			  .addHeader("Authorization", oauthToken)
			  .build();
				Response response = client.newCall(request).execute();
				String responseBody = response.body().string();
				if (response.code() == 200) {
	                return handleJsonResponse(responseBody);
	            }else {
	                throw new Exception("Return code " + response.code());
	            }
        } catch(Exception e) {
        	
        }
        return null;
    }

    

    private static Object getPropertyValue(Map<String, String> options, String propertyName, Object defaultValue) {
        Object result = null;
        String env = options.get(propertyName) != null ? options.get(propertyName): System.getProperty(propertyName);
        if ("OAUTH_AUTHORIZATION".equals(propertyName) || "OAUTH_INTROSPECT_AUTHORIZATION".equals(propertyName)) {
            env = env.replace("%20", " ");
        }
        if(env == null){
            result = defaultValue;
        } else{
            if(defaultValue instanceof Boolean){
                result = Boolean.valueOf(env);
            }else if(defaultValue instanceof Integer){
                result = Integer.valueOf(env);
            }else if(defaultValue instanceof Double){
                result = Double.valueOf(env);
            }else if(defaultValue instanceof Float){
                result = Float.valueOf(env);
            }else{
                result = env;
            }
        }
        return result;
    }

    private static Map<String,Object> handleJsonResponse(String response){
    	Map<String, Object> result = null;
        ObjectMapper objectMapper = new ObjectMapper();
        System.out.println("in handleJsonResponseNew"+response);
        try{            
            result = objectMapper.readValue(response, new TypeReference<Map<String,Object>>(){});
        }catch (Exception e){
            e.printStackTrace();
        }
        return result;
    }
}
