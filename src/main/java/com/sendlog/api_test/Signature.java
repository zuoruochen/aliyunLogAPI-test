package com.sendlog.api_test;

import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Encoder;

import org.apache.http.Header;
import org.apache.http.client.methods.HttpRequestBase;

/*
 * construct signature which is use for authorization
 * it will throw exception if the parameters are not enough
 */
public class Signature
{
	String signature;
	public Signature(HttpRequestBase method,String accessKeySecret) throws Exception{
		// TODO Auto-generated constructor stub
		//required
		String verb = method.getMethod();
		//option
		String contentMd5 = "";
		Header[] md5 = method.getHeaders("Content-MD5");
		if(md5.length != 0)
			contentMd5 = md5[0].getValue();
		//option
		String contenttype = "";
		Header[] type = method.getHeaders("Content-Type"); 
		if(type.length !=0 )
			contenttype = type[0].getValue();
		
		//required
		String date = method.getHeaders("Date")[0].getValue();
		
		List<String> xLog = new ArrayList<String>();
		
		//required
		String xLogApiversion = method.getHeaders("x-log-apiversion")[0].getName().toLowerCase()+":"+method.getHeaders("x-log-apiversion")[0].getValue();
		xLog.add(xLogApiversion);
		String xLogSignaturemethod = method.getHeaders("x-log-signaturemethod")[0].getName().toLowerCase()+":"+method.getHeaders("x-log-signaturemethod")[0].getValue();
		xLog.add(xLogSignaturemethod);
		
		//option
		if(method.getHeaders("x-log-date").length != 0 )
			xLog.add(method.getHeaders("x-log-date")[0].getName().toLowerCase()+":"+method.getHeaders("x-log-date")[0].getValue());
		if(method.getHeaders("x-acs-security-token").length != 0 )
			xLog.add(method.getHeaders("x-acs-security-token")[0].getName().toLowerCase()+":"+method.getHeaders("x-acs-security-token")[0].getValue());
		if(method.getHeaders("x-log-compresstype").length != 0 )
			xLog.add(method.getHeaders("x-log-compresstype")[0].getName().toLowerCase()+":"+method.getHeaders("x-log-compresstype")[0].getValue());
		if(method.getHeaders("x-log-bodyrawsize").length != 0 )
			xLog.add(method.getHeaders("x-log-bodyrawsize")[0].getName().toLowerCase()+":"+method.getHeaders("x-log-bodyrawsize")[0].getValue());
		
	
		String[] xLogParam = xLog.toArray(new String[xLog.size()]);

		Arrays.sort(xLogParam);
		
		String canonicalizedLOGHeaders = "";
		//we will add "\n" after canonicalizedLOGHeaders,so we should not add "\n" after in signature construction
		for(int i = 0 ; i < xLogParam.length ; ++i)
			canonicalizedLOGHeaders = canonicalizedLOGHeaders + xLogParam[i] + "\n";
		
		String canonicalizedResource = method.getURI().getPath();
		String orginalQueryString = method.getURI().getQuery();
		if (orginalQueryString != null) {
			String[] kv = orginalQueryString.split("&");
			Arrays.sort(kv);
			String queryString = "";
			for (int i = 0; i < kv.length; ++i)
				queryString = queryString + kv[i] + "&";
			queryString = queryString.substring(0, queryString.length() - 1);
			System.out.println(queryString);
			canonicalizedResource = canonicalizedLOGHeaders + "?" + queryString;
		} 
		
		String signString = verb + "\n"
				+ contentMd5 + "\n"
				+ contenttype + "\n"
				+ date + "\n"
				+ canonicalizedLOGHeaders
				+ canonicalizedResource;
		
		//Signature = base64(hmac-sha1(UTF8-Encoding-Of(SignString)，AccessKeySecret))
		
		System.out.println(signString);
		byte[] hmacsha1 = Hmacsha1.HmacSHA1Encrypt(signString, accessKeySecret);
		Encoder base64 = Base64.getEncoder();
		signature = base64.encodeToString(hmacsha1);	
	}
	
	
	public String getSignature(){
		return signature;
	}
}