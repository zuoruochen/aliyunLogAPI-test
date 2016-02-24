package com.sendlog.api_test;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import java.security.*;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

import net.jpountz.lz4.LZ4Compressor;
import net.jpountz.lz4.LZ4Factory;
/**
 * Hello world!
 *
 */
public class Sender 
{
	
	private static String GetMd5Value(byte[] bytes) {
		try {
			MessageDigest md;
			md = MessageDigest.getInstance("MD5");
			String res = new BigInteger(1, md.digest(bytes)).toString(16)
					.toUpperCase();

			StringBuilder zeros = new StringBuilder();
			for (int i = 0; i + res.length() < 32; i++) {
				zeros.append("0");
			}
			return zeros.toString() + res;
		} catch (NoSuchAlgorithmException e) {
			// never happen
			throw new RuntimeException("Not Supported signature method "
					+ "MD5", e);
		}
	}
	
    public static void main(String[] args) throws ClientProtocolException, IOException, URISyntaxException, NoSuchAlgorithmException {
    	
    	Calendar cd = Calendar.getInstance();
    	SimpleDateFormat sdf = new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss 'GMT'", Locale.US);
    	sdf.setTimeZone(TimeZone.getTimeZone("GMT")); // 设置时区为GMT
     	String time = sdf.format(cd.getTime());	
    	
    	String accessKeyId = "";
        String accessKeySecret = "";
        String logstoreName = "";
        String path = "/logstores";
        if(logstoreName != null)
            String path = path + "/" + logstoreName;
        String host = "";

        URI uri = new URIBuilder()
    		   .setScheme("http")
    		   .setHost(host)
    		   .setPath(path)
    		   .build();

        System.out.println(uri);
        HttpPost httppost = new HttpPost(uri);
        
        Logs.LogGroup.Builder logs = Logs.LogGroup.newBuilder();
        logs.setTopic("");
        logs.setSource("10.230.201.117");
        Logs.Log.Builder log = logs.addLogsBuilder();
        log.setTime((int) (new Date().getTime() / 1000));
        Logs.Log.Content.Builder contentBuilder = log
				.addContentsBuilder();
        contentBuilder.setKey("type");
        contentBuilder.setValue("playlogv6");
        contentBuilder = log.addContentsBuilder();
        contentBuilder.setKey("content");
        contentBuilder.setValue("make you feel my love!");
        
        
        byte[] data = logs.build().toByteArray();
       
        final int decompressedLength = data.length;

        LZ4Factory factory = LZ4Factory.fastestInstance();
        // compress data
        LZ4Compressor compressor = factory.fastCompressor();
        int maxCompressedLength = compressor.maxCompressedLength(decompressedLength);
        byte[] compressed = new byte[maxCompressedLength];
        int compressedLength = compressor.compress(data, 0, decompressedLength, compressed, 0, maxCompressedLength);
        byte[] after = new byte[compressedLength];
        System.arraycopy(compressed, 0, after, 0, compressedLength);
           
        
        ByteArrayEntity entity = new ByteArrayEntity(after);
        
        httppost.setEntity(entity);
        
        String md5 = DigestUtils.md5Hex(after).toUpperCase();
        
        //option: if has body,we should compute the md5 of the body and set Content-MD5 and Content-Type
        httppost.setHeader("Content-MD5",md5);
        httppost.setHeader("Content-Type", "application/x-protobuf");
        
        //common
        httppost.setHeader("date",time);
        httppost.setHeader("x-log-apiversion","0.6.0");
        httppost.setHeader("x-log-signaturemethod","hmac-sha1");

        //option
        //httppost.setHeader("x-log-date","Mon, 4 Jan 2010 09:33:59 GMT");
        //httppost.setHeader("x-acs-security-token", "abc");
        
        //option: if set x-log-compresstype ,we should set x-log-bodyrawsize
        httppost.setHeader("x-log-compresstype", "lz4");
        httppost.setHeader("x-log-bodyrawsize", String.valueOf(data.length));
        
        Signature sigObj;
        try {
			sigObj = new Signature(httppost, accessKeySecret);
	        String sig = sigObj.getSignature();
	        System.out.println(sig);
	        
	        
	        String authorization = "LOG " + accessKeyId + ":" + sig;
	        System.out.println(authorization);
	        httppost.setHeader("Authorization",authorization);		
	             
		} catch (Exception e) {
			// TODO Auto-generated catch block
			//e.printStackTrace();
			System.out.println("need more header!");
		}
       		
		CloseableHttpClient client = HttpClients.createDefault();
        CloseableHttpResponse response = client.execute(httppost);
        System.out.println("Response Code: " +
	    response.getStatusLine().getStatusCode());
		
        BufferedReader rd = new BufferedReader(
            new InputStreamReader(response.getEntity().getContent()));
        String line = "";
        while((line = rd.readLine()) != null) {
	    System.out.println(line);
        }
        response.close();
        
    }
}
